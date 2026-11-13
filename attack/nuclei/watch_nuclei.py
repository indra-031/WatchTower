#!/usr/bin/env python3
"""
WatchTower - Nuclei Scanner

Scans HTTP URLs (from nuclei-urls.txt, or http/lives-http.json as fallback).
Only keeps severities: critical, high, medium, low (info is dropped).

Scope enforcement:
  - out_of_scope (and legacy "ooscope") is applied when loading URLs,
    before saving findings, and when purging existing result files.
  - OOS wins over scope.
  - Scope checks use the URL hostname from `matched-at` (not Nuclei's `host`
    field, which is often `IP:port` and would fail domain-based checks).
  - Existing entries in lives-nuclei.json and nuclei-result.json are purged
    of stale OOS entries on each write.

Writes:
  database/<program>/attack/nuclei/nuclei.json          (scan log)
  database/<program>/attack/nuclei/lives-nuclei.json    (master, keyed)
  database/<program>/attack/nuclei/nuclei-result.json   (flat list for UI)
  database/<program>/attack/nuclei/nuclei_done.json     (URLs tested)

Usage:
  python3 watch_nuclei.py <domain>
  python3 watch_nuclei.py <domain> --fresh
  python3 watch_nuclei.py <domain> --force
  python3 watch_nuclei.py --all
  python3 watch_nuclei.py --all --fresh
  python3 watch_nuclei.py --all --force
"""

import sys
import json
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


# =========================
# Project root discovery
# =========================

def _find_project_root(start: Path) -> Path:
    current = start.resolve()
    for _ in range(10):
        if (current / "configs" / "colors.py").exists() and (current / "database").exists():
            return current
        if (current / "app.py").exists():
            return current
        if current.parent == current:
            break
        current = current.parent
    return start.resolve().parent.parent


BASE_DIR = _find_project_root(Path(__file__))
DATABASE_DIR = BASE_DIR / "database"
SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG = SCRIPT_DIR / "nuclei-public.yaml"

ATTACK_SUBDIR = "attack"
NUCLEI_SUBDIR = "nuclei"


def nuclei_output_dir(program_dir: Path) -> Path:
    return program_dir / ATTACK_SUBDIR / NUCLEI_SUBDIR


if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from configs.colors import colors
from configs.scope import load_scope_from_path, is_in_scope


# =========================
# Configuration
# =========================

ALLOWED_SEVERITIES = {"critical", "high", "medium", "low"}
NUCLEI_RATE_LIMIT = 150
NUCLEI_CONCURRENCY = 25
NUCLEI_TIMEOUT = 3600


# =========================
# Helpers
# =========================

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize_name(name):
    return (name.strip().lower()
            .replace(" ", "-").replace("/", "-")
            .replace("\\", "-").replace(":", "-"))


def load_json(path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")


def find_program_by_scope(scope_name):
    if not DATABASE_DIR.exists():
        return None
    for d in DATABASE_DIR.iterdir():
        if not d.is_dir() or not (d / "program.json").exists():
            continue
        try:
            data = json.loads((d / "program.json").read_text())
        except Exception:
            continue
        scopes = (
            data.get("scope", [])
            + data.get("out_of_scope", data.get("ooscope", []))
        )
        for s in scopes:
            clean = s.lstrip("*.").lower()
            if scope_name == clean or scope_name.endswith("." + clean):
                return data
    return None


def get_all_programs():
    if not DATABASE_DIR.exists():
        return []
    progs = []
    for d in DATABASE_DIR.iterdir():
        if not d.is_dir() or d.name.startswith("_"):
            continue
        if not (d / "program.json").exists():
            continue
        try:
            data = json.loads((d / "program.json").read_text())
            scopes = [s.strip() for s in data.get("scope", []) if s and s.strip()]
            if not scopes:
                continue
            progs.append({
                "program_name": data.get("program_name", d.name),
                "scopes": scopes,
                "path": d,
            })
        except Exception:
            continue
    return progs


def _host_of(url):
    """Extract hostname from a URL string. Empty string on failure."""
    if not url:
        return ""
    try:
        p = urlparse(url)
        return (p.hostname or "").lower()
    except Exception:
        return ""


def _finding_hostname(f):
    """
    Return the domain-level hostname of a nuclei finding.

    Nuclei's `host` field is typically `IP:port` (e.g. '172.67.201.236:443'),
    which would fail any domain-based scope check. Prefer the URL hostname
    from `matched-at` / `url`. Fall back to `host` with the port stripped.
    """
    for key in ("matched-at", "matched_at", "url"):
        val = f.get(key, "")
        if val:
            h = _host_of(val)
            if h:
                return h
    raw = f.get("host", "") or ""
    if ":" in raw:
        return raw.split(":", 1)[0].lower()
    return raw.lower()


# =========================
# URL sources
# =========================

def get_urls_for_domain(program_dir, domain, scope=None, oos=None):
    """
    Prefer nuclei-urls.txt (built by nuclei_url_maker.py).
    Filter to the requested domain and in-scope hosts.
    Fall back to http/lives-http.json.
    """
    scope = scope or []
    oos = oos or []
    oos_skipped = 0

    urls_file = nuclei_output_dir(program_dir) / "nuclei-urls.txt"
    if urls_file.exists():
        try:
            lines = urls_file.read_text(encoding="utf-8").splitlines()
            urls = [l.strip() for l in lines if l.strip()]
            domain_l = domain.lower()
            urls = [u for u in urls if domain_l in u.lower()]

            filtered = []
            for u in urls:
                h = _host_of(u)
                if h and (scope or oos) and not is_in_scope(h, scope, oos):
                    oos_skipped += 1
                    continue
                filtered.append(u)

            if filtered:
                if oos_skipped:
                    print(f"     {colors.YELLOW}⏭  {oos_skipped} URL(s) skipped (out of scope){colors.RESET}")
                return sorted(set(filtered))
        except Exception:
            pass

    http_file = program_dir / "http" / "lives-http.json"
    if not http_file.exists():
        return []
    try:
        lives = json.loads(http_file.read_text())
    except Exception:
        return []

    urls = []
    for host, info in lives.items():
        if info.get("domain") != domain:
            continue
        if (scope or oos) and not is_in_scope(host, scope, oos):
            continue
        url = info.get("url") or info.get("final_url") or f"https://{host}"
        if url:
            urls.append(url)
    return sorted(set(urls))


# =========================
# Nuclei runner
# =========================

def run_nuclei(urls, config_path=None):
    if not urls:
        return [], 0, None

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        for u in urls:
            f.write(u + "\n")
        urls_file = f.name

    cmd = [
        "nuclei",
        "-l", urls_file,
        "-jsonl",
        "-silent",
        "-duc",
        "-rl", str(NUCLEI_RATE_LIMIT),
        "-c", str(NUCLEI_CONCURRENCY),
    ]
    if config_path and config_path.exists():
        cmd += ["-config", str(config_path)]

    print(f"     {colors.GRAY}$ nuclei -l urls.txt "
          f"-jsonl -silent -duc -rl {NUCLEI_RATE_LIMIT} -c {NUCLEI_CONCURRENCY}{colors.RESET}")

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=NUCLEI_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        Path(urls_file).unlink(missing_ok=True)
        return [], 0, "timeout"
    except FileNotFoundError:
        Path(urls_file).unlink(missing_ok=True)
        return [], 0, "nuclei not found"
    except Exception as e:
        Path(urls_file).unlink(missing_ok=True)
        return [], 0, str(e)

    Path(urls_file).unlink(missing_ok=True)

    if proc.stderr.strip():
        for line in proc.stderr.strip().splitlines()[:3]:
            if any(k in line.lower() for k in ("error", "fail", "warn")):
                print(f"     {colors.YELLOW}{line[:150]}{colors.RESET}")

    raw = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            raw.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    filtered = []
    for f in raw:
        sev = (f.get("info", {}).get("severity") or "").lower()
        if sev in ALLOWED_SEVERITIES:
            filtered.append(f)

    return filtered, len(raw), None


# =========================
# Persistence
# =========================

def finding_key(f):
    return (
        f.get("template-id", f.get("template", "")),
        f.get("host", ""),
        f.get("matched-at", ""),
    )


def save_results(program_dir, program_name, domain, findings, urls_tested,
                 scope=None, oos=None):
    """
    Save nuclei.json, lives-nuclei.json, nuclei-result.json.

    `findings` is expected to be already scope-filtered by the caller.
    Existing entries in lives-nuclei.json and nuclei-result.json are
    purged of stale OOS entries on write (using matched-at hostname).
    """
    scope = scope or []
    oos = oos or []
    nuclei_dir = nuclei_output_dir(program_dir)
    nuclei_dir.mkdir(parents=True, exist_ok=True)
    ts = now()

    # 1. nuclei.json (scan log)
    log_file = nuclei_dir / "nuclei.json"
    log_data = load_json(log_file)
    if not isinstance(log_data, dict) or "scans" not in log_data:
        log_data = {"scans": []}
    log_data["scans"].append({
        "timestamp": ts,
        "domain": domain,
        "program_name": program_name,
        "source": "nuclei",
        "urls_tested": len(urls_tested),
        "findings_count": len(findings),
        "findings": findings,
    })
    save_json(log_file, log_data)
    print(f"     {colors.GREEN}💾 nuclei.json → {log_file}{colors.RESET}")

    # 2. lives-nuclei.json (master, keyed)
    lives_file = nuclei_dir / "lives-nuclei.json"
    lives = load_json(lives_file)
    if not isinstance(lives, dict):
        lives = {}

    # Purge stale OOS entries
    if scope or oos:
        before = len(lives)
        lives = {
            k: v for k, v in lives.items()
            if is_in_scope(_finding_hostname(v), scope, oos)
        }
        removed = before - len(lives)
        if removed:
            print(f"     {colors.YELLOW}⏭  {removed} stale finding(s) removed (out of scope){colors.RESET}")

    new_count = 0
    for f in findings:
        t, h, m = finding_key(f)
        if not t:
            continue
        key = f"{t}||{h}||{m}"
        if key not in lives:
            new_count += 1
        lives[key] = {
            "template": t,
            "name": f.get("info", {}).get("name", ""),
            "severity": f.get("info", {}).get("severity", ""),
            "host": h,
            "matched_at": m,
            "url": f.get("url", m),
            "description": f.get("info", {}).get("description", ""),
            "tags": f.get("info", {}).get("tags", []),
            "type": f.get("type", ""),
            "first_seen": lives.get(key, {}).get("first_seen", ts),
            "last_seen": ts,
        }
    save_json(lives_file, lives)
    if new_count:
        print(f"     {colors.GREEN}🆕 {new_count} new in lives-nuclei.json{colors.RESET}")
    print(f"     {colors.CYAN}📋 lives-nuclei.json: {len(lives)} total{colors.RESET}")

    # 3. nuclei-result.json (flat list for UI)
    result_file = nuclei_dir / "nuclei-result.json"
    existing = []
    if result_file.exists():
        try:
            data = json.loads(result_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                existing = data
        except Exception:
            existing = []

    # Purge stale OOS entries
    if scope or oos:
        before = len(existing)
        existing = [
            e for e in existing
            if is_in_scope(_finding_hostname(e), scope, oos)
        ]
        removed = before - len(existing)
        if removed:
            print(f"     {colors.YELLOW}⏭  {removed} stale finding(s) removed from nuclei-result.json{colors.RESET}")

    existing_keys = {finding_key(e) for e in existing}
    added = 0
    for f in findings:
        if finding_key(f) not in existing_keys:
            existing.append(f)
            existing_keys.add(finding_key(f))
            added += 1

    save_json(result_file, existing)
    if added:
        print(f"     {colors.GREEN}🆕 {added} new in nuclei-result.json{colors.RESET}")
    print(f"     {colors.CYAN}📋 nuclei-result.json: {len(existing)} total{colors.RESET}")


def mark_done(program_dir, urls, scope=None, oos=None):
    """
    Mark URLs as tested. OOS URLs are never marked done, so they can be
    picked up if scope changes in the future.
    """
    scope = scope or []
    oos = oos or []
    done_file = nuclei_output_dir(program_dir) / "nuclei_done.json"
    done = load_json(done_file)
    if not isinstance(done, dict):
        done = {}
    ts = now()
    for u in urls:
        h = _host_of(u)
        if h and (scope or oos) and not is_in_scope(h, scope, oos):
            continue
        done[u] = {"tested_at": ts}
    save_json(done_file, done)


# =========================
# Program processing
# =========================

def process_program(program, fresh_only=False):
    pn = program["program_name"]
    pd = program["path"]
    scopes = program["scopes"]

    scope, oos = load_scope_from_path(pd / "program.json")

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn} — {len(scopes)} scope(s){colors.RESET}")
    if oos:
        print(f"{colors.BLUE}   OOS: {', '.join(oos)}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    done_file = nuclei_output_dir(pd) / "nuclei_done.json"
    done = load_json(done_file)
    if not isinstance(done, dict):
        done = {}

    total_tested = 0
    total_findings = 0
    total_skipped = 0

    for i, scope_name in enumerate(scopes, 1):
        clean = scope_name.strip().lstrip("*.").lower()
        print(f"\n{colors.CYAN}[{i}/{len(scopes)}] {clean}{colors.RESET}")

        urls = get_urls_for_domain(pd, clean, scope=scope, oos=oos)
        if not urls:
            print(f"{colors.YELLOW}⚠️ No URLs for {clean} "
                  f"(run watch_httpx_all.py first){colors.RESET}")
            continue

        if fresh_only:
            pending = [u for u in urls if u not in done]
            skipped = len(urls) - len(pending)
            if skipped:
                total_skipped += skipped
                print(f"     {colors.GRAY}⏭  {skipped} already tested, "
                      f"{len(pending)} pending{colors.RESET}")
            if not pending:
                print(f"     {colors.GREEN}✅ All URLs already tested{colors.RESET}")
                continue
            urls = pending

        print(f"     {colors.CYAN}📋 {len(urls)} URL(s) to scan{colors.RESET}")

        findings, raw_count, err = run_nuclei(urls, DEFAULT_CONFIG)
        if err:
            print(f"{colors.RED}❌ nuclei failed for {clean}: {err}{colors.RESET}")
            continue

        info_dropped = raw_count - len(findings)

        # Scope filter — MUST use matched-at hostname, not Nuclei's host field
        oos_dropped = 0
        if scope or oos:
            before = len(findings)
            findings = [
                f for f in findings
                if is_in_scope(_finding_hostname(f), scope, oos)
            ]
            oos_dropped = before - len(findings)
            if oos_dropped:
                print(f"     {colors.YELLOW}⏭  {oos_dropped} finding(s) filtered (out of scope){colors.RESET}")

        if info_dropped:
            print(f"     {colors.GRAY}({info_dropped} info-severity finding(s) dropped){colors.RESET}")

        if not findings:
            print(f"     {colors.GREEN}✅ No in-scope findings{colors.RESET}")
        else:
            sev_counts = {}
            for f in findings:
                sev = (f.get("info", {}).get("severity") or "unknown").lower()
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
            for sev in ("critical", "high", "medium", "low"):
                c = sev_counts.get(sev, 0)
                if c:
                    if sev == "critical":
                        color = colors.RED
                    elif sev == "high":
                        color = colors.YELLOW
                    elif sev == "medium":
                        color = colors.BLUE
                    else:
                        color = colors.GREEN
                    print(f"     {color}{sev}: {c}{colors.RESET}")

        save_results(pd, pn, clean, findings, urls, scope=scope, oos=oos)
        mark_done(pd, urls, scope=scope, oos=oos)

        total_tested += len(urls)
        total_findings += len(findings)

    print()
    print(f"{colors.GREEN}✅ {pn} — tested: {total_tested}, "
          f"findings: {total_findings}{colors.RESET}")
    if total_skipped:
        print(f"   {colors.CYAN}skipped: {total_skipped} (already done){colors.RESET}")
    return total_tested, total_findings, total_skipped


# =========================
# Main
# =========================

if __name__ == "__main__":
    args = sys.argv[1:]
    all_mode = "--all" in args
    fresh_only = "--fresh" in args
    if "--force" in args:
        fresh_only = False

    non_flags = [a for a in args if not a.startswith("--")]

    mode = "Fresh" if fresh_only else "All"
    print(f"{colors.CYAN}[{now()}] WatchTower — Nuclei ({mode}){colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found in database/{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_nuclei.py <domain> [--fresh|--force]")
            print("       python3 watch_nuclei.py --all [--fresh|--force]")
            sys.exit(1)
        domain = non_flags[0].strip().lower().lstrip("*.")
        program = find_program_by_scope(domain)
        if not program:
            print(f"{colors.RED}❌ Scope '{domain}' not found{colors.RESET}")
            sys.exit(1)
        pname = program.get("program_name", "unknown")
        programs = [{
            "program_name": pname,
            "scopes": [domain],
            "path": DATABASE_DIR / sanitize_name(pname),
        }]

    grand_tested = 0
    grand_findings = 0
    grand_skipped = 0

    for prog in programs:
        t, f, s = process_program(prog, fresh_only=fresh_only)
        grand_tested += t
        grand_findings += f
        grand_skipped += s

    print(f"\n{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ Nuclei complete{colors.RESET}")
    print(f"{colors.GREEN}   Tested  : {grand_tested} URL(s){colors.RESET}")
    print(f"{colors.GREEN}   Findings: {grand_findings}{colors.RESET}")
    if grand_skipped:
        print(f"{colors.CYAN}   Skipped : {grand_skipped} (already done){colors.RESET}")
    print(f"{colors.GRAY}   Done files: database/<program>/attack/nuclei/nuclei_done.json{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")