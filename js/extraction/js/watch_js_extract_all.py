#!/usr/bin/env python3
"""
WatchTower - JS Extraction Orchestrator

Runs all 8 JS extraction modules in order.

Usage:
  python3 watch_js_extract_all.py
  python3 watch_js_extract_all.py --only endpoints-js,paths-js
  python3 watch_js_extract_all.py --skip comments-js
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
    {"name": "Comments",   "key": "comments-js",   "script": SCRIPT_DIR / "watch_comments_js_all.py",   "timeout": 600},
    {"name": "Emails",     "key": "emails-js",     "script": SCRIPT_DIR / "watch_emails_js_all.py",     "timeout": 300},
    {"name": "Endpoints",  "key": "endpoints-js",  "script": SCRIPT_DIR / "watch_endpoints_js_all.py",  "timeout": 600},
    {"name": "Fragments",  "key": "fragments-js",  "script": SCRIPT_DIR / "watch_fragments_js_all.py",  "timeout": 300},
    {"name": "Libraries",  "key": "libraries-js",  "script": SCRIPT_DIR / "watch_libraries_js_all.py",  "timeout": 300},
    {"name": "Parameters", "key": "parameters-js", "script": SCRIPT_DIR / "watch_parameters_js_all.py", "timeout": 600},
    {"name": "Paths",      "key": "paths-js",      "script": SCRIPT_DIR / "watch_paths_js_all.py",      "timeout": 600},
    {"name": "URLs",       "key": "urls-js",       "script": SCRIPT_DIR / "watch_urls_js_all.py",       "timeout": 600},
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
        result = subprocess.run([sys.executable, str(script)], timeout=timeout)
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

    print(f"{colors.CYAN}[{now()}] WatchTower — JS Extraction{colors.RESET}\n")
    print(f"{colors.CYAN}🔧 Modules: {', '.join(m['name'] for m in enabled)}{colors.RESET}\n")

    start_ts = time.time()
    results = [run_module(m) for m in enabled]
    total_duration = time.time() - start_ts
    success = sum(1 for r in results if r["status"] == "success")

    print(f"{colors.GREEN}╔══════════════════════════════════════════════════════╗{colors.RESET}")
    print(f"{colors.GREEN}║        ✅ JS EXTRACTION COMPLETE                     ║{colors.RESET}")
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