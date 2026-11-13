#!/usr/bin/env python3
"""
WatchTower - JS Discovery : Katana (active)
Runs ProjectDiscovery's katana on each in-scope HTTP host to crawl
HTML/JS/XHR endpoints, collecting URLs for downstream analysis.

Filters out static assets (images, fonts, CSS) that aren't interesting
for JS recon. Depth-limited to 3, respects robots.txt.

Skips hosts that redirect to another host (redirect sources). Only the
final canonical host is crawled — this avoids crawling 200 subdomains
that all redirect to the bare domain.

Writes:
  database/<program>/js/discovery/active/katana/urls.txt
  database/<program>/js/discovery/active/katana/meta.json

Incremental:
  - cache is DISABLED (FRESH_HOURS = 0). Katana is active crawling and
    must run every pipeline invocation so newly deployed JS is detected.
  - --force is accepted for compatibility but has no effect.

Scope enforcement:
  - Only in-scope, alive, non-redirect hosts are crawled.
  - Results are filtered to URLs whose hostname is in scope (OOS wins).

Usage:
  python3 watch_katana.py <domain>
  python3 watch_katana.py <domain> --force
  python3 watch_katana.py --all
  python3 watch_katana.py --all --force

Requires:
  katana : go install github.com/projectdiscovery/katana/cmd/katana@latest
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
from configs.hosts import build_redirect_map, is_canonical


# =========================
# Configuration
# =========================

TOOL_NAME = "katana"
FRESH_HOURS = 0              # Disable cache — always crawl
KATANA_TIMEOUT = 600
MAX_URLS = 50000

KATANA_ARGS = [
    "-jc", "-xhr",
    "-kf", "robotstxt",
    "-d", "3",
    "-c", "15",
    "-p", "5",
    "-rl", "100",
    "-timeout", "10",
    "-ef", "woff,woff2,ttf,png,jpg,jpeg,svg,gif,css",
    "-silent",
]


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
    if hours <= 0:
        return False
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
    """Return [(host, url)] of in-scope, alive, non-redirect hosts."""
    lf = program_dir / "http" / "lives-http.json"
    if not lf.exists():
        return []
    try:
        lives = json.loads(lf.read_text())
    except Exception:
        return []

    scope, oos = load_scope_from_path(program_dir / "program.json")
    redirect_map = build_redirect_map(program_dir)

    hosts = []
    redirect_skipped = 0
    for host, info in lives.items():
        if info.get("status", "alive") != "alive":
            continue
        if (scope or oos) and not is_in_scope(host, scope, oos):
            continue
        if not is_canonical(host, redirect_map):
            redirect_skipped += 1
            continue
        url = info.get("url") or info.get("final_url") or f"https://{host}"
        if url:
            hosts.append((host, url))

    if redirect_skipped:
        print(f"     {colors.GRAY}⏭  {redirect_skipped} redirect-source host(s) skipped{colors.RESET}")

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
    return program_dir / "js" / "discovery" / "active" / TOOL_NAME


def run_katana(target_url):
    cmd = ["katana", "-u", target_url] + KATANA_ARGS
    print(f"       {colors.GRAY}$ katana -u {target_url} -d 3 -jc -xhr{colors.RESET}")

    urls = []
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        last_print = 0
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue
            urls.append(line)
            if len(urls) - last_print >= 20:
                print(f"\r       {colors.GRAY}... {len(urls)} URLs so far{colors.RESET}",
                      end="", flush=True)
                last_print = len(urls)
        proc.wait(timeout=KATANA_TIMEOUT)
        print()  # newline after progress
        return urls
    except FileNotFoundError:
        print(f"{colors.RED}❌ katana not installed. "
              f"Install: go install github.com/projectdiscovery/katana/cmd/katana@latest{colors.RESET}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
        except Exception:
            pass
        print(f"       {colors.YELLOW}⏰ timeout, keeping {len(urls)} URLs so far{colors.RESET}")
        return urls
    except Exception as e:
        print(f"       {colors.RED}❌ {e}{colors.RESET}")
        return urls


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
        print(f"{colors.YELLOW}⚠️ No in-scope, non-redirect HTTP hosts{colors.RESET}\n")
        return {"checked": 0, "skipped": 0, "urls": 0}

    scope, oos = load_scope_from_path(pd / "program.json")

    meta = load_json(meta_file)
    per_host = meta.get("per_host", {}) if isinstance(meta, dict) else {}

    checked = skipped = 0

    for host, url in hosts:
        cached = per_host.get(host)
        if not force and isinstance(cached, dict) and is_fresh(cached.get("last_run", "")):
            skipped += 1
            print(f"     {colors.GRAY}[skip] {host} "
                  f"({cached.get('urls_count', 0)} cached){colors.RESET}")
            continue

        print(f"     {colors.CYAN}[crawl] {host}{colors.RESET}")
        raw = run_katana(url)
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

    # Aggregate — only keep per_host entries for currently canonical hosts
    canonical_hosts = {h for h, _ in hosts}
    per_host = {h: v for h, v in per_host.items() if h in canonical_hosts}

    all_urls = set()
    for h, info in per_host.items():
        for u in info.get("urls", []):
            all_urls.add(u)
    all_urls_sorted = sorted(all_urls)[:MAX_URLS]

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

    print(f"{colors.CYAN}[{now()}] WatchTower — Katana Active Crawl"
          f"{' [Force]' if force else ''}{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_katana.py <domain> [--force]")
            print("       python3 watch_katana.py --all [--force]")
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
    print(f"{colors.GREEN}✅ Katana active crawl complete{colors.RESET}")
    print(f"{colors.GREEN}   Crawled  : {total_checked}{colors.RESET}")
    if total_skipped:
        print(f"{colors.CYAN}   Skipped  : {total_skipped} (cached){colors.RESET}")
    print(f"{colors.GREEN}   URLs     : {total_urls}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")


if __name__ == "__main__":
    main()