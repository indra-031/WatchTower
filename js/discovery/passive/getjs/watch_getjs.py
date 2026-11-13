#!/usr/bin/env python3
"""
WatchTower - JS Discovery : GetJS (passive)
Runs `getJS -complete` on each in-scope host to collect JS URLs from the
frontpage + Wayback snapshot. Results are filtered by scope.

Writes:
  database/<program>/js/discovery/passive/getjs/urls.txt
  database/<program>/js/discovery/passive/getjs/meta.json

Incremental:
  - per-host cache in meta.json. Hosts run within FRESH_HOURS are skipped
    unless --force. Most results come from archive snapshots, which change
    rarely — 7-day cache keeps daily runs fast.

Scope enforcement:
  - Only in-scope, alive hosts are queried.
  - Results are filtered to URLs whose hostname is in scope (OOS wins).

Usage:
  python3 watch_getjs.py <domain>
  python3 watch_getjs.py <domain> --force
  python3 watch_getjs.py --all
  python3 watch_getjs.py --all --force

Requires:
  getJS : go install github.com/003random/getJS@latest
"""

import sys
import json
import subprocess
from datetime import datetime, timedelta
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

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from configs.colors import colors
from configs.scope import load_scope_from_path, is_in_scope


# =========================
# Configuration
# =========================

TOOL_NAME = "getjs"
FRESH_HOURS = 168            # 7 days — archive-based, changes rarely
GETJS_TIMEOUT = 120
MAX_URLS = 50000


# =========================
# Helpers
# =========================

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize(name):
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


def is_fresh(ts, hours=FRESH_HOURS):
    if not ts:
        return False
    try:
        return (datetime.now() - datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")) <= timedelta(hours=hours)
    except Exception:
        return False


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
        scopes = data.get("scope", []) + data.get("out_of_scope", data.get("ooscope", []))
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


def get_hosts(program_dir):
    lf = program_dir / "http" / "lives-http.json"
    if not lf.exists():
        return []
    try:
        lives = json.loads(lf.read_text())
    except Exception:
        return []

    scope, oos = load_scope_from_path(program_dir / "program.json")

    hosts = []
    for host, info in lives.items():
        if info.get("status", "alive") != "alive":
            continue
        if (scope or oos) and not is_in_scope(host, scope, oos):
            continue
        url = info.get("url") or info.get("final_url") or f"https://{host}"
        if url:
            hosts.append((host, url))
    return hosts


def url_hostname(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def filter_urls_by_scope(urls, scope, oos):
    if not (scope or oos):
        return urls
    return [u for u in urls if url_hostname(u) and is_in_scope(url_hostname(u), scope, oos)]


def output_dir(program_dir):
    return program_dir / "js" / "discovery" / "passive" / TOOL_NAME


def run_getjs(url):
    try:
        result = subprocess.check_output(
            ["getJS", "-url", url, "-complete", "-resolve",
             "-threads", "10", "-timeout", "10s"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=GETJS_TIMEOUT,
        )
        return list(dict.fromkeys(
            line.strip() for line in result.splitlines() if line.strip()
        ))
    except FileNotFoundError:
        print(f"{colors.RED}❌ getJS not installed. "
              f"Install: go install github.com/003random/getJS@latest{colors.RESET}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        return []
    except Exception:
        return []


# =========================
# Program processing
# =========================

def process_program(program, force=False):
    pn = program["program_name"]
    pd = program["path"]
    out_dir = output_dir(pd)
    urls_file = out_dir / "urls.txt"
    meta_file = out_dir / "meta.json"

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    hosts = get_hosts(pd)
    if not hosts:
        print(f"{colors.YELLOW}⚠️ No in-scope HTTP hosts{colors.RESET}\n")
        return {"checked": 0, "skipped": 0, "urls": 0}

    scope, oos = load_scope_from_path(pd / "program.json")

    meta = load_json(meta_file)
    per_host = meta.get("per_host", {}) if isinstance(meta, dict) else {}

    checked = 0
    skipped = 0

    for host, url in hosts:
        cached = per_host.get(host)
        if not force and isinstance(cached, dict) and is_fresh(cached.get("last_run", "")):
            skipped += 1
            print(f"     {colors.GRAY}[skip] {host} "
                  f"({cached.get('urls_count', 0)} cached){colors.RESET}")
            continue

        print(f"     {colors.CYAN}[run] {host}{colors.RESET}")
        raw = run_getjs(url)
        filtered = filter_urls_by_scope(raw, scope, oos)

        per_host[host] = {
            "last_run": now(),
            "raw_count": len(raw),
            "urls_count": len(filtered),
            "urls": filtered[:MAX_URLS],
        }
        checked += 1
        print(f"       {colors.GREEN}✅ {len(filtered)} URL(s) in scope "
              f"(raw: {len(raw)}){colors.RESET}")

    all_urls = set()
    for h, info in per_host.items():
        for u in info.get("urls", []):
            all_urls.add(u)
    all_urls_sorted = sorted(all_urls)

    if len(all_urls_sorted) > MAX_URLS:
        print(f"     {colors.YELLOW}⚠️ capping at {MAX_URLS} URLs "
              f"({len(all_urls_sorted)} found){colors.RESET}")
        all_urls_sorted = all_urls_sorted[:MAX_URLS]

    out_dir.mkdir(parents=True, exist_ok=True)
    urls_file.write_text("\n".join(all_urls_sorted) + ("\n" if all_urls_sorted else ""),
                         encoding="utf-8")

    save_json(meta_file, {
        "tool": TOOL_NAME,
        "program": pn,
        "timestamp": now(),
        "hosts_total": len(hosts),
        "urls_total": len(all_urls_sorted),
        "per_host": per_host,
    })

    print(f"\n     {colors.GREEN}💾 saved → {urls_file} ({len(all_urls_sorted)} URLs){colors.RESET}\n")
    return {"checked": checked, "skipped": skipped, "urls": len(all_urls_sorted)}


# =========================
# Main
# =========================

def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    force = "--force" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — GetJS Discovery"
          f"{' [Force]' if force else ''}{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_getjs.py <domain> [--force]")
            print("       python3 watch_getjs.py --all [--force]")
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
            "path": DATABASE_DIR / sanitize(pname),
        }]

    total_checked = total_skipped = total_urls = 0
    for prog in programs:
        s = process_program(prog, force=force)
        total_checked += s["checked"]
        total_skipped += s["skipped"]
        total_urls += s["urls"]

    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ GetJS discovery complete{colors.RESET}")
    print(f"{colors.GREEN}   Checked  : {total_checked}{colors.RESET}")
    if total_skipped:
        print(f"{colors.CYAN}   Skipped  : {total_skipped} (cached){colors.RESET}")
    print(f"{colors.GREEN}   URLs     : {total_urls}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")


if __name__ == "__main__":
    main()