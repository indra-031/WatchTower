#!/usr/bin/env python3
"""
WatchTower - Secret : Semgrep
Writes: database/<program>/secret/semgrep/{js,inline-js,html}.json
"""

import sys
import subprocess
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from _shared import (
    BASE_DIR, DATABASE_DIR, now, sanitize,
    find_program_by_scope, get_all_programs,
    get_sources, finalize_out_dir,
)

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
from configs.colors import colors


TOOL = "semgrep"
EXT = "json"
CONFIG_DIR = BASE_DIR / "configs" / "semgrep"
CONFIG_FOR_LABEL = {
    "js": "js-secrets.yml",
    "inline-js": "js-secrets.yml",
    "html": "html-secrets.yml",
}


def run_tool(scan_dir, out_file, label):
    cfg = CONFIG_DIR / CONFIG_FOR_LABEL.get(label, "js-secrets.yml")
    cmd = ["semgrep", "scan", str(scan_dir), "--config", str(cfg), "--json", "--quiet"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    except FileNotFoundError:
        print(f"{colors.RED}❌ semgrep not installed{colors.RESET}")
        return False
    except Exception:
        return False
    output = r.stdout.strip()
    if not output or output == '{"results": []}':
        return False
    out_file.write_text(output, encoding="utf-8")
    return True


def process_program(program):
    pn = program["program_name"]
    pd = program["path"]
    out_dir = pd / "secret" / TOOL

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    found = False
    for label, src_dir in get_sources(pd):
        if not src_dir.exists() or not any(src_dir.glob("*")):
            continue
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{label}.{EXT}"
        if run_tool(src_dir, out_file, label):
            found = True
            print(f"     {colors.GREEN}✅ {label}{colors.RESET}")
        else:
            print(f"     {colors.GRAY}✗ {label}{colors.RESET}")

    finalize_out_dir(out_dir, found)
    return found


def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — Semgrep{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_semgrep.py <domain>")
            print("       python3 watch_semgrep.py --all")
            sys.exit(1)
        domain = non_flags[0].strip().lower().lstrip("*.")
        program = find_program_by_scope(domain)
        if not program:
            print(f"{colors.RED}❌ Scope '{domain}' not found{colors.RESET}")
            sys.exit(1)
        pname = program.get("program_name", "unknown")
        programs = [{"program_name": pname, "path": DATABASE_DIR / sanitize(pname)}]

    hits = 0
    for prog in programs:
        if process_program(prog):
            hits += 1
    print(f"{colors.GREEN}✅ Semgrep complete ({hits}/{len(programs)} with findings){colors.RESET}")


if __name__ == "__main__":
    main()