#!/usr/bin/env python3
"""
WatchTower - Active JS Discovery Orchestrator

Runs active discovery tools in order:
  1. Katana   — crawl HTML/JS/XHR endpoints per host
  2. SubJS    — extract <script src> from every collected URL
                (passive + katana)

SubJS depends on Katana, so order matters.

Writes URL counts by reading each tool's meta.json.

Usage:
  python3 watch_active_all.py
  python3 watch_active_all.py --force
  python3 watch_active_all.py --only katana
  python3 watch_active_all.py --skip subjs
"""

import sys
import json
import time
import subprocess
from datetime import datetime
from pathlib import Path


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

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from configs.colors import colors


# =========================
# Configuration
# =========================

MODULES = [
    {
        "name": "Katana",
        "key": "katana",
        "script": SCRIPT_DIR / "katana" / "watch_katana_all.py",
        "enabled": True,
        "timeout": 3600,
    },
    {
        "name": "SubJS",
        "key": "subjs",
        "script": SCRIPT_DIR / "subjs" / "watch_subjs_all.py",
        "enabled": True,
        "timeout": 1800,
    },
]


# =========================
# Helpers
# =========================

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_all_program_dirs():
    if not DATABASE_DIR.exists():
        return []
    return sorted(
        d.name for d in DATABASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith("_") and (d / "program.json").exists()
    )


def collect_url_counts(tool_key):
    total = 0
    per_program = {}
    for prog in get_all_program_dirs():
        meta_file = (
            DATABASE_DIR / prog / "js" / "discovery" / "active" / tool_key / "meta.json"
        )
        if not meta_file.exists():
            continue
        try:
            meta = json.loads(meta_file.read_text(encoding="utf-8"))
            count = int(meta.get("urls_total", 0))
        except Exception:
            count = 0
        per_program[prog] = count
        total += count
    return total, per_program


def parse_filters(args):
    only = set()
    skip = set()
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
    timeout = module.get("timeout", 3600)

    if not script.exists():
        print(f"{colors.RED}❌ Script not found: {script}{colors.RESET}")
        return {"name": name, "exit_code": -1, "duration_s": 0, "status": "missing"}

    cmd = [sys.executable, str(script)]
    if force:
        cmd.append("--force")

    print(f"{colors.BLUE}┌──────────────────────────────────────────────────────┐{colors.RESET}")
    print(f"{colors.BLUE}│{colors.RESET} {colors.WHITE}{name}{colors.RESET}")
    print(f"{colors.BLUE}│{colors.RESET} {colors.GRAY}Command: {' '.join(cmd)}{colors.RESET}")
    print(f"{colors.BLUE}└──────────────────────────────────────────────────────┘{colors.RESET}")
    print()

    start = time.time()
    try:
        result = subprocess.run(cmd, timeout=timeout)
        exit_code = result.returncode
        status = "success" if exit_code == 0 else "failed"
    except subprocess.TimeoutExpired:
        print(f"{colors.YELLOW}⏰ Timeout after {timeout}s{colors.RESET}")
        exit_code = -1
        status = "timeout"
    except Exception as e:
        print(f"{colors.RED}❌ {e}{colors.RESET}")
        exit_code = -1
        status = "error"

    duration = time.time() - start

    if status == "success":
        print(f"{colors.GREEN}✅ {name} completed in {duration:.1f}s{colors.RESET}\n")
    elif status == "timeout":
        print(f"{colors.YELLOW}⚠️  {name} timed out after {duration:.1f}s{colors.RESET}\n")
    else:
        print(f"{colors.YELLOW}⚠️  {name} exited with code {exit_code} "
              f"({duration:.1f}s){colors.RESET}\n")

    return {"name": name, "exit_code": exit_code,
            "duration_s": duration, "status": status}


# =========================
# Main
# =========================

def main():
    args = sys.argv[1:]
    only, skip, force = parse_filters(args)

    enabled = [m for m in MODULES if m.get("enabled", True)]
    if only:
        enabled = [m for m in enabled if m["key"] in only]
    if skip:
        enabled = [m for m in enabled if m["key"] not in skip]

    if not enabled:
        print(f"{colors.RED}❌ No modules to run after filtering.{colors.RESET}")
        sys.exit(1)

    programs = get_all_program_dirs()
    if not programs:
        print(f"{colors.RED}❌ No programs found in database/{colors.RESET}")
        print(f"{colors.YELLOW}   Run programs/watch_sync_programs.py first.{colors.RESET}")
        sys.exit(1)

    print(f"{colors.CYAN}[{now()}] WatchTower — Active JS Discovery{colors.RESET}")
    print(f"{colors.GRAY}   Mode: {'[Force]' if force else '[Cached]'}{colors.RESET}")
    print()
    print(f"{colors.CYAN}📦 Programs : {len(programs)} ({', '.join(programs)}){colors.RESET}")
    print(f"{colors.CYAN}🔧 Tools    : {', '.join(m['name'] for m in enabled)}{colors.RESET}")
    print(f"{colors.CYAN}📂 Output   : database/<program>/js/discovery/active/{colors.RESET}")
    print()

    start_ts = time.time()
    results = []

    for module in enabled:
        r = run_module(module, force=force)
        results.append(r)

    total_duration = time.time() - start_ts

    # ==================== Final summary ====================
    print(f"{colors.GREEN}╔══════════════════════════════════════════════════════╗{colors.RESET}")
    print(f"{colors.GREEN}║        ✅ ACTIVE DISCOVERY COMPLETE                  ║{colors.RESET}")
    print(f"{colors.GREEN}╚══════════════════════════════════════════════════════╝{colors.RESET}")
    print()

    success_count = sum(1 for r in results if r["status"] == "success")
    failed_count = len(results) - success_count

    for r in results:
        icon = "✅" if r["status"] == "success" else "⚠️ "
        color = colors.GREEN if r["status"] == "success" else colors.YELLOW
        print(f"{color}{icon} {r['name']:<15} "
              f"({r['duration_s']:>6.1f}s)   exit={r['exit_code']}{colors.RESET}")

    print()

    print(f"{colors.CYAN}📊 URLs by tool:{colors.RESET}")
    grand_total = 0
    for module in enabled:
        count, per_prog = collect_url_counts(module["key"])
        grand_total += count
        print(f"   {module['name']:<15} {count:>6} URL(s)")
        for prog, pc in sorted(per_prog.items()):
            if pc > 0:
                print(f"     {colors.GRAY}└─ {prog}: {pc}{colors.RESET}")

    print()
    print(f"{colors.GREEN}   Total URLs : {grand_total}{colors.RESET}")
    print(f"{colors.GREEN}   Duration   : {total_duration:.1f}s{colors.RESET}")
    print(f"{colors.GREEN}   Tools      : {success_count}/{len(results)} succeeded{colors.RESET}")
    if failed_count:
        print(f"{colors.YELLOW}   Failed     : {failed_count}{colors.RESET}")

    if success_count == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()