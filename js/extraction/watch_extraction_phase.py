#!/usr/bin/env python3
"""
WatchTower - Extraction Phase Orchestrator

Runs all extraction modules in dependency order:

  1. html extraction       (independent)
  2. js extraction         (independent)
  3. inline-js extraction  (independent)
  4. xnlinkfinder          (needs download/{js,html,inline-js})
  5. extraction merge      (needs all extraction outputs)
  6. urls-with-param       (needs discovery/merge + extraction/merge)
  7. parameter wordlist    (needs extraction/merge/parameters-merge.txt)

Usage:
  python3 watch_extraction_phase.py
  python3 watch_extraction_phase.py --force
  python3 watch_extraction_phase.py --only html,js
  python3 watch_extraction_phase.py --skip wordlist-parameter
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
JS_DIR = BASE_DIR / "js"
WL_DIR = BASE_DIR / "wordlist"
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
from configs.colors import colors


MODULES = [
    {"name": "HTML Extract",       "key": "html",        "script": JS_DIR / "extraction" / "html" / "watch_html_extract_all.py",       "timeout": 900},
    {"name": "JS Extract",         "key": "js",          "script": JS_DIR / "extraction" / "js" / "watch_js_extract_all.py",           "timeout": 900},
    {"name": "Inline-JS Extract",  "key": "inline-js",   "script": JS_DIR / "extraction" / "inline-js" / "watch_inline_js_extract_all.py","timeout": 900},
    {"name": "xnLinkFinder",       "key": "xnlinkfinder","script": JS_DIR / "extraction" / "xnlinkfinder" / "watch_xnlinkfinder_all.py","timeout": 1800},
    {"name": "Extraction Merge",   "key": "merge",       "script": JS_DIR / "extraction" / "merge" / "watch_extraction_merge_all.py", "timeout": 300},
    {"name": "URLs With Params",   "key": "urls-param",  "script": JS_DIR / "extraction" / "merge" / "watch_urls_with_param_all.py",   "timeout": 300},
    {"name": "Parameter Wordlist", "key": "wl-param",    "script": WL_DIR / "parameter" / "watch_parameter_wordlist_all.py",          "timeout": 120},
]


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def parse_filters(args):
    only, skip = set(), set()
    force = "--force" in args
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
    return only, skip, force


def run_module(module, force=False):
    name = module["name"]
    script = module["script"]
    timeout = module.get("timeout", 900)

    if not script.exists():
        print(f"{colors.RED}❌ Script not found: {script}{colors.RESET}")
        return {"name": name, "exit_code": -1, "duration_s": 0, "status": "missing"}

    cmd = [sys.executable, str(script)]
    if force:
        cmd.append("--force")

    print(f"{colors.BLUE}┌──────────────────────────────────────────────────────┐{colors.RESET}")
    print(f"{colors.BLUE}│{colors.RESET} {colors.WHITE}{name}{colors.RESET}")
    print(f"{colors.BLUE}└──────────────────────────────────────────────────────┘{colors.RESET}\n")

    start = time.time()
    try:
        result = subprocess.run(cmd, timeout=timeout)
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
    only, skip, force = parse_filters(args)

    enabled = list(MODULES)
    if only:
        enabled = [m for m in enabled if m["key"] in only]
    if skip:
        enabled = [m for m in enabled if m["key"] not in skip]

    if not enabled:
        print(f"{colors.RED}❌ No modules to run after filtering.{colors.RESET}")
        sys.exit(1)

    print(f"{colors.CYAN}[{now()}] WatchTower — Extraction Phase{colors.RESET}")
    print(f"{colors.GRAY}   Mode: {'[Force]' if force else '[Cached]'}{colors.RESET}\n")
    print(f"{colors.CYAN}🔧 Modules: {', '.join(m['name'] for m in enabled)}{colors.RESET}\n")

    start_ts = time.time()
    results = [run_module(m, force=force) for m in enabled]
    total_duration = time.time() - start_ts
    success = sum(1 for r in results if r["status"] == "success")

    print(f"{colors.GREEN}╔══════════════════════════════════════════════════════╗{colors.RESET}")
    print(f"{colors.GREEN}║        ✅ EXTRACTION PHASE COMPLETE                  ║{colors.RESET}")
    print(f"{colors.GREEN}╚══════════════════════════════════════════════════════╝{colors.RESET}\n")

    for r in results:
        icon = "✅" if r["status"] == "success" else "⚠️ "
        color = colors.GREEN if r["status"] == "success" else colors.YELLOW
        print(f"{color}{icon} {r['name']:<20} ({r['duration_s']:>6.1f}s) exit={r['exit_code']}{colors.RESET}")

    print()
    print(f"{colors.GREEN}   Duration : {total_duration:.1f}s{colors.RESET}")
    print(f"{colors.GREEN}   Modules  : {success}/{len(results)} succeeded{colors.RESET}")

    if success == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()