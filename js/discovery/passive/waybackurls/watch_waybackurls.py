#!/usr/bin/env python3
"""
WatchTower - JS Discovery : Wayback URLs (passive)
Runs `waybackurls` per scope domain, keeps .js/.html/.htm URLs, and
filters results by scope.

NOTE: The original vajra.sh used `-no-subs` which excludes subdomains.
WatchTower drops that flag because scope-based filtering already protects
OOS assets, and subdomain JS coverage is valuable.

Writes:
  database/<program>/js/discovery/passive/waybackurls/urls.txt
  database/<program>/js/discovery/passive/waybackurls/meta.json

Incremental:
  - per-scope cache. Scopes run within FRESH_HOURS are skipped unless --force.
  - FRESH_HOURS is 7 days because historical archive content changes slowly
    relative to daily pipeline runs.

Scope enforcement:
  - Results are filtered to URLs whose hostname is in scope (OOS wins).

Usage:
  python3 watch_waybackurls.py <domain>
  python3 watch_waybackurls.py <domain> --force
  python3 watch_waybackurls.py --all
  python3 watch_waybackurls.py --all --force

Requires:
  waybackurls : go install github.com/tomnomnom/waybackurls@latest
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

TOOL_NAME = "waybackurls"
FRESH_HOURS = 168            # 7 days — historical archive, changes slowly
WAYBACK_TIMEOUT = 300
MAX_URLS = 50000
EXTENSIONS = (".js", ".html", ".htm")


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


def run_waybackurls(domain):
    try:
        result = subprocess.check_output(
            ["waybackurls", domain],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=WAYBACK_TIMEOUT,
        )
        urls = [
            line.strip()
            for line in result.splitlines()
            if line.strip().lower().split("?")[0].endswith(EXTENSIONS)
        ]
        return list(dict.fromkeys(urls))
    except FileNotFoundError:
        print(f"{colors.RED}❌ waybackurls not installed. "
              f"Install: go install github.com/tomnomnom/waybackurls@latest{colors.RESET}")
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
    scopes = [s.strip().lstrip("*.").lower() for s in program["scopes"] if s and s.strip()]
    out_dir = output_dir(pd)
    urls_file = out_dir / "urls.txt"
    meta_file = out_dir / "meta.json"

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    scope, oos = load_scope_from_path(pd / "program.json")

    meta = load_json(meta_file)
    per_scope = meta.get("per_scope", {}) if isinstance(meta, dict) else {}

    checked = skipped = 0

    for dom in scopes:
        cached = per_scope.get(dom)
        if not force and isinstance(cached, dict) and is_fresh(cached.get("last_run", "")):
            skipped += 1
            print(f"     {colors.GRAY}[skip] {dom} "
                  f"({cached.get('in_scope_count', 0)} cached){colors.RESET}")
            continue

        print(f"     {colors.CYAN}[run] {dom}{colors.RESET}")
        raw = run_waybackurls(dom)
        filtered = filter_urls_by_scope(raw, scope, oos)

        per_scope[dom] = {
            "last_run": now(),
            "raw_count": len(raw),
            "in_scope_count": len(filtered),
            "urls": filtered[:MAX_URLS],
        }
        checked += 1
        print(f"       {colors.GREEN}✅ {len(filtered)} URL(s) in scope "
              f"(raw: {len(raw)}){colors.RESET}")

    all_urls = set()
    for dom, info in per_scope.items():
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
        "scopes": scopes,
        "urls_total": len(all_urls_sorted),
        "per_scope": per_scope,
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

    print(f"{colors.CYAN}[{now()}] WatchTower — Wayback URLs Discovery"
          f"{' [Force]' if force else ''}{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_waybackurls.py <domain> [--force]")
            print("       python3 watch_waybackurls.py --all [--force]")
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
    print(f"{colors.GREEN}✅ Wayback URLs discovery complete{colors.RESET}")
    print(f"{colors.GREEN}   Checked  : {total_checked}{colors.RESET}")
    if total_skipped:
        print(f"{colors.CYAN}   Skipped  : {total_skipped} (cached){colors.RESET}")
    print(f"{colors.GREEN}   URLs     : {total_urls}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")


if __name__ == "__main__":
    main()