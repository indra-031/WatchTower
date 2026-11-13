#!/usr/bin/env python3
"""
WatchTower - HTML Extraction Orchestrator

Runs all HTML extraction modules in order. Inline JS first, then the
text extractors (they're independent but inline-js populates download/inline-js/
which downstream tools expect).

Usage:
  python3 watch_html_extract_all.py
  python3 watch_html_extract_all.py --only inline-js,comments-html
  python3 watch_html_extract_all.py --skip urls-html
"""

import sys
import time
import subprocess
from datetime import datetime
from pathlib import Path


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
SCRIPT_DIR = Path(__file__).resolve().parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from configs.colors import colors


MODULES = [
    {"name": "Inline JS",  "key": "inline-js",       "script": SCRIPT_DIR / "watch_inline_js_all.py",      "timeout": 600},
    {"name": "Comments",   "key": "comments-html",   "script": SCRIPT_DIR / "watch_comments_html_all.py",  "timeout": 300},
    {"name": "Emails",     "key": "emails-html",     "script": SCRIPT_DIR / "watch_emails_html_all.py",    "timeout": 300},
    {"name": "Endpoints",  "key": "endpoints-html",  "script": SCRIPT_DIR / "watch_endpoints_html_all.py", "timeout": 300},
    {"name": "Fragments",  "key": "fragments-html",  "script": SCRIPT_DIR / "watch_fragments_html_all.py", "timeout": 300},
    {"name": "Libraries",  "key": "libraries-html",  "script": SCRIPT_DIR / "watch_libraries_html_all.py", "timeout": 300},
    {"name": "Parameters", "key": "parameters-html", "script": SCRIPT_DIR / "watch_parameters_html_all.py","timeout": 300},
    {"name": "Paths",      "key": "paths-html",      "script": SCRIPT_DIR / "watch_paths_html_all.py",     "timeout": 300},
    {"name": "URLs",       "key": "urls-html",       "script": SCRIPT_DIR / "watch_urls_html_all.py",      "timeout": 300},
]


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_filters(args):
    only, skip = set(), set()
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--only" and i + 1 < len(args):
            only = {x.strip().lower() for x in args[i + 1].split(",") if x.strip()}
            i += 2
        elif a == "--skip" and i + 1 < len(args):
            skip = {x.strip().lower() for x in args[i + 1].split(",") if x.strip()}
            i += 2
        else:
            i += 1
    return only, skip


def run_module(module):
    name = module["name"]
    script = module["script"]
    timeout = module.get("timeout", 300)

    if not script.exists():
        print(f"{colors.RED}❌ Script not found: {script}{colors.RESET}")
        return {"name": name, "exit_code": -1, "duration_s": 0, "status": "missing"}

    print(f"{colors.BLUE}┌──────────────────────────────────────────────────────┐{colors.RESET}")
    print(f"{colors.BLUE}│{colors.RESET} {colors.WHITE}{name}{colors.RESET}")
    print(f"{colors.BLUE}└──────────────────────────────────────────────────────┘{colors.RESET}\n")

    start = time.time()
    try:
        result = subprocess.run(
            [sys.executable, str(script)],
            timeout=timeout,
        )
        exit_code = result.returncode
        status = "success" if exit_code == 0 else "failed"
    except subprocess.TimeoutExpired:
        print(f"{colors.YELLOW}⏰ Timeout after {timeout}s{colors.RESET}")
        exit_code, status = -1, "timeout"
    except Exception as e:
        print(f"{colors.RED}❌ {e}{colors.RESET}")
        exit_code, status = -1, "error"

    duration = time.time() - start
    icon = "✅" if status == "success" else "⚠️ "
    color = colors.GREEN if status == "success" else colors.YELLOW
    print(f"{color}{icon} {name} ({duration:.1f}s) exit={exit_code}{colors.RESET}\n")

    return {"name": name, "exit_code": exit_code,
            "duration_s": duration, "status": status}


def main():
    args = sys.argv[1:]
    only, skip = parse_filters(args)

    enabled = list(MODULES)
    if only:
        enabled = [m for m in enabled if m["key"] in only]
    if skip:
        enabled = [m for m in enabled if m["key"] not in skip]

    if not enabled:
        print(f"{colors.RED}❌ No modules to run after filtering.{colors.RESET}")
        sys.exit(1)

    print(f"{colors.CYAN}[{now()}] WatchTower — HTML Extraction{colors.RESET}\n")
    print(f"{colors.CYAN}🔧 Modules: {', '.join(m['name'] for m in enabled)}{colors.RESET}\n")

    start_ts = time.time()
    results = [run_module(m) for m in enabled]
    total_duration = time.time() - start_ts

    success = sum(1 for r in results if r["status"] == "success")

    print(f"{colors.GREEN}╔══════════════════════════════════════════════════════╗{colors.RESET}")
    print(f"{colors.GREEN}║        ✅ HTML EXTRACTION COMPLETE                   ║{colors.RESET}")
    print(f"{colors.GREEN}╚══════════════════════════════════════════════════════╝{colors.RESET}\n")

    for r in results:
        icon = "✅" if r["status"] == "success" else "⚠️ "
        color = colors.GREEN if r["status"] == "success" else colors.YELLOW
        print(f"{color}{icon} {r['name']:<15} ({r['duration_s']:>6.1f}s) exit={r['exit_code']}{colors.RESET}")

    print()
    print(f"{colors.GREEN}   Duration : {total_duration:.1f}s{colors.RESET}")
    print(f"{colors.GREEN}   Modules  : {success}/{len(results)} succeeded{colors.RESET}")

    if success == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()