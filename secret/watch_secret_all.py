#!/usr/bin/env python3
"""
WatchTower - Secret Scanners Orchestrator
Runs all secret scanners in sequence.

Order (vajra-style, no dependency between tools — each is independent):
  shhgit, trufflehog, semgrep, secretfinder, jsluice, gitleaks,
  dumpsterdiver, detectsecrets, vscan

Usage:
  python3 watch_secret_all.py
  python3 watch_secret_all.py --only shhgit,vscan
  python3 watch_secret_all.py --skip semgrep,jsluice
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
DATABASE_DIR = BASE_DIR / "database"
SCRIPT_DIR = Path(__file__).resolve().parent

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
from configs.colors import colors


MODULES = [
    {"name": "shhgit",        "key": "shhgit",        "script": SCRIPT_DIR / "watch_shhgit.py",        "timeout": 1800},
    {"name": "trufflehog",    "key": "trufflehog",    "script": SCRIPT_DIR / "watch_trufflehog.py",    "timeout": 1800},
    {"name": "semgrep",       "key": "semgrep",       "script": SCRIPT_DIR / "watch_semgrep.py",       "timeout": 1800},
    {"name": "secretfinder",  "key": "secretfinder",  "script": SCRIPT_DIR / "watch_secretfinder.py",  "timeout": 1800},
    {"name": "jsluice",       "key": "jsluice",       "script": SCRIPT_DIR / "watch_jsluice.py",       "timeout": 1800},
    {"name": "gitleaks",      "key": "gitleaks",      "script": SCRIPT_DIR / "watch_gitleaks.py",      "timeout": 1800},
    {"name": "dumpsterdiver", "key": "dumpsterdiver", "script": SCRIPT_DIR / "watch_dumpsterdiver.py", "timeout": 1800},
    {"name": "detect-secrets","key": "detectsecrets", "script": SCRIPT_DIR / "watch_detectsecrets.py", "timeout": 1800},
    {"name": "vscan",         "key": "vscan",         "script": SCRIPT_DIR / "watch_vscan.py",         "timeout": 1800},
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


def get_all_program_dirs():
    if not DATABASE_DIR.exists():
        return []
    return sorted(
        d.name for d in DATABASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith("_") and (d / "program.json").exists()
    )


def count_finding_files(tool_key):
    """Count how many programs have any file in secret/<tool>/."""
    total_programs = 0
    total_files = 0
    per_program = {}
    for prog in get_all_program_dirs():
        d = DATABASE_DIR / prog / "secret" / tool_key
        if not d.exists():
            continue
        files = [f for f in d.iterdir() if f.is_file()]
        if files:
            total_programs += 1
            total_files += len(files)
            per_program[prog] = len(files)
    return total_programs, total_files, per_program


def run_module(module):
    name = module["name"]
    script = module["script"]
    timeout = module.get("timeout", 1800)

    if not script.exists():
        print(f"{colors.RED}❌ Script not found: {script}{colors.RESET}")
        return {"name": name, "exit_code": -1, "duration_s": 0, "status": "missing"}

    print(f"{colors.BLUE}┌──────────────────────────────────────────────────────┐{colors.RESET}")
    print(f"{colors.BLUE}│{colors.RESET} {colors.WHITE}{name}{colors.RESET}")
    print(f"{colors.BLUE}└──────────────────────────────────────────────────────┘{colors.RESET}\n")

    start = time.time()
    try:
        result = subprocess.run([sys.executable, str(script), "--all"], timeout=timeout)
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

    programs = get_all_program_dirs()
    if not programs:
        print(f"{colors.RED}❌ No programs found{colors.RESET}")
        sys.exit(1)

    print(f"{colors.CYAN}[{now()}] WatchTower — Secret Scanners{colors.RESET}\n")
    print(f"{colors.CYAN}📦 Programs: {len(programs)} ({', '.join(programs)}){colors.RESET}")
    print(f"{colors.CYAN}🔧 Tools   : {', '.join(m['name'] for m in enabled)}{colors.RESET}\n")

    start_ts = time.time()
    results = [run_module(m) for m in enabled]
    total_duration = time.time() - start_ts
    success = sum(1 for r in results if r["status"] == "success")

    print(f"{colors.GREEN}╔══════════════════════════════════════════════════════╗{colors.RESET}")
    print(f"{colors.GREEN}║        ✅ SECRET SCAN COMPLETE                       ║{colors.RESET}")
    print(f"{colors.GREEN}╚══════════════════════════════════════════════════════╝{colors.RESET}\n")

    for r in results:
        icon = "✅" if r["status"] == "success" else "⚠️ "
        color = colors.GREEN if r["status"] == "success" else colors.YELLOW
        print(f"{color}{icon} {r['name']:<15} ({r['duration_s']:>6.1f}s) exit={r['exit_code']}{colors.RESET}")

    print()
    print(f"{colors.CYAN}📊 Findings by tool:{colors.RESET}")
    for module in enabled:
        key = module["key"]
        # map key to output dir name
        dir_map = {
            "shhgit": "shhgit",
            "trufflehog": "trufflehog",
            "semgrep": "semgrep",
            "secretfinder": "secretfinder",
            "jsluice": "jsluice",
            "gitleaks": "gitleaks",
            "dumpsterdiver": "dumpsterdiver",
            "detectsecrets": "detect-secrets",
            "vscan": "vscan",
        }
        dname = dir_map.get(key, key)
        progs_with, files, per_prog = count_finding_files(dname)
        if files:
            print(f"   {module['name']:<15} {progs_with} program(s), {files} file(s)")
            for p, c in sorted(per_prog.items()):
                print(f"     {colors.GRAY}└─ {p}: {c}{colors.RESET}")
        else:
            print(f"   {module['name']:<15} {colors.GRAY}no findings{colors.RESET}")

    print()
    print(f"{colors.GREEN}   Duration : {total_duration:.1f}s{colors.RESET}")
    print(f"{colors.GREEN}   Tools    : {success}/{len(results)} succeeded{colors.RESET}")

    if success == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()