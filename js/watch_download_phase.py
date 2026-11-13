#!/usr/bin/env python3
"""
WatchTower - Download Phase Orchestrator

Runs the download phase in the correct order:
  1. merge    — aggregate all discovery URLs
  2. download — fetch .js / .html files to disk

Usage:
  python3 watch_download_phase.py
  python3 watch_download_phase.py --force
  python3 watch_download_phase.py --only merge
  python3 watch_download_phase.py --skip merge
"""

import sys
import json
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
JS_DIR = BASE_DIR / "js"

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from configs.colors import colors


MODULES = [
    {
        "name": "Merge",
        "key": "merge",
        "script": JS_DIR / "discovery" / "merge" / "watch_merge_all.py",
        "enabled": True,
        "timeout": 600,
    },
    {
        "name": "Download",
        "key": "download",
        "script": JS_DIR / "download" / "watch_download_all.py",
        "enabled": True,
        "timeout": 3600,
    },
]


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def get_all_program_dirs():
    if not DATABASE_DIR.exists():
        return []
    return sorted(
        d.name for d in DATABASE_DIR.iterdir()
        if d.is_dir() and not d.name.startswith("_") and (d / "program.json").exists()
    )


def collect_download_stats():
    total_js = total_html = total_bytes = 0
    per_program = {}
    for prog in get_all_program_dirs():
        meta_file = DATABASE_DIR / prog / "js" / "download" / "meta.json"
        if not meta_file.exists():
            continue
        try:
            m = json.loads(meta_file.read_text(encoding="utf-8"))
        except Exception:
            continue
        js = int(m.get("downloaded", 0))
        # Files on disk aren't tracked separately per kind in meta, so use total
        total_js += js
        total_bytes += int(m.get("bytes", 0))
        per_program[prog] = {"downloaded": js, "bytes": int(m.get("bytes", 0))}
    return total_js, total_bytes, per_program


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
    timeout = module.get("timeout", 1800)

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
        print(f"{colors.RED}❌ No programs found{colors.RESET}")
        sys.exit(1)

    print(f"{colors.CYAN}[{now()}] WatchTower — Download Phase{colors.RESET}")
    print(f"{colors.GRAY}   Mode: {'[Force]' if force else '[Cached]'}{colors.RESET}\n")
    print(f"{colors.CYAN}📦 Programs : {len(programs)} ({', '.join(programs)}){colors.RESET}")
    print(f"{colors.CYAN}🔧 Tools    : {', '.join(m['name'] for m in enabled)}{colors.RESET}\n")

    start_ts = time.time()
    results = [run_module(m, force=force) for m in enabled]
    total_duration = time.time() - start_ts

    print(f"{colors.GREEN}╔══════════════════════════════════════════════════════╗{colors.RESET}")
    print(f"{colors.GREEN}║        ✅ DOWNLOAD PHASE COMPLETE                    ║{colors.RESET}")
    print(f"{colors.GREEN}╚══════════════════════════════════════════════════════╝{colors.RESET}\n")

    success_count = sum(1 for r in results if r["status"] == "success")
    for r in results:
        icon = "✅" if r["status"] == "success" else "⚠️ "
        color = colors.GREEN if r["status"] == "success" else colors.YELLOW
        print(f"{color}{icon} {r['name']:<15} "
              f"({r['duration_s']:>6.1f}s)   exit={r['exit_code']}{colors.RESET}")

    print()

    files_count, bytes_count, per_prog = collect_download_stats()
    print(f"{colors.CYAN}📊 Downloaded files:{colors.RESET}")
    for prog, info in sorted(per_prog.items()):
        mb = info["bytes"] / (1024 * 1024)
        print(f"   {prog:<20} {info['downloaded']:>6} file(s)   {mb:>8.2f} MB")

    mb_total = bytes_count / (1024 * 1024)
    print()
    print(f"{colors.GREEN}   Total files : {files_count}{colors.RESET}")
    print(f"{colors.GREEN}   Total size  : {mb_total:.2f} MB{colors.RESET}")
    print(f"{colors.GREEN}   Duration    : {total_duration:.1f}s{colors.RESET}")
    print(f"{colors.GREEN}   Tools       : {success_count}/{len(results)} succeeded{colors.RESET}")

    if success_count == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()