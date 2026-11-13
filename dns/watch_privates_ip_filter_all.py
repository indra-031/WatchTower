#!/usr/bin/env python3
"""
WatchTower - Filter Private IPs (All Programs)
Runs private-IP filtering on every program in database/.

Reads:  database/<program>/dns/lives.json
Writes: database/<program>/dns/lives.json
        database/<program>/dns/lives-private.json
"""

import sys
import json
from pathlib import Path


# =========================
# Imports from local module
# =========================

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from watch_privates_ip_filter import (
    process_program, current_time, DATABASE_DIR,
)


# =========================
# Imports from configs/
# =========================

PROJECT_ROOT = SCRIPT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from configs.colors import colors


# =========================
# Helpers
# =========================

def get_all_programs():
    if not DATABASE_DIR.exists():
        return []
    programs = []
    for d in sorted(DATABASE_DIR.iterdir()):
        if not d.is_dir():
            continue
        program_file = d / "program.json"
        if not program_file.exists():
            continue
        try:
            data = json.loads(program_file.read_text())
        except Exception:
            continue
        programs.append({
            "program_name": data.get("program_name", d.name),
            "scopes": [s.strip() for s in data.get("scope", []) if s and s.strip()],
        })
    return programs


# =========================
# Main
# =========================

if __name__ == "__main__":
    print(f"{colors.CYAN}[{current_time()}] WatchTower — Filter Private IPs (All){colors.RESET}\n")

    programs = get_all_programs()
    if not programs:
        print(f"{colors.RED}❌ No programs found in database/{colors.RESET}")
        print(f"{colors.YELLOW}   Run programs/watch_sync_programs.py first.{colors.RESET}")
        sys.exit(1)

    print(f"{colors.CYAN}📦 Programs: {len(programs)}{colors.RESET}\n")

    totals = {
        "kept": 0,
        "filtered": 0,
        "moved_to_private": 0,
        "moved_to_public": 0,
        "stripped": 0,
    }

    for prog in programs:
        pn = prog["program_name"]

        print(f"{colors.BLUE}{'='*50}{colors.RESET}")
        print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
        if prog["scopes"]:
            print(f"{colors.BLUE}   scopes: {', '.join(prog['scopes'])}{colors.RESET}")
        print(f"{colors.BLUE}{'='*50}{colors.RESET}")

        # domain=None means: filter all hosts in this program's lives.json
        result = process_program(pn, domain=None)

        print(f"     {colors.GREEN}📋 kept     : {result['kept']}{colors.RESET}")
        print(f"     {colors.YELLOW}🔒 filtered : {result['filtered']}{colors.RESET}")
        if result["moved_to_private"]:
            print(f"     {colors.GRAY}   moved public→private: {result['moved_to_private']}{colors.RESET}")
        if result["moved_to_public"]:
            print(f"     {colors.GRAY}   moved private→public: {result['moved_to_public']}{colors.RESET}")
        if result["stripped"]:
            print(f"     {colors.GRAY}   mixed-IP hosts stripped: {result['stripped']}{colors.RESET}")
        print()

        for key in totals:
            totals[key] += result.get(key, 0)

    # Final summary
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ Filter complete{colors.RESET}")
    print(f"{colors.GREEN}   Programs              : {len(programs)}{colors.RESET}")
    print(f"{colors.GREEN}   Kept in lives.json    : {totals['kept']}{colors.RESET}")
    print(f"{colors.YELLOW}   Moved to private      : {totals['filtered']}{colors.RESET}")
    if totals["moved_to_private"]:
        print(f"{colors.GRAY}     public→private this run: {totals['moved_to_private']}{colors.RESET}")
    if totals["moved_to_public"]:
        print(f"{colors.GRAY}     private→public this run: {totals['moved_to_public']}{colors.RESET}")
    if totals["stripped"]:
        print(f"{colors.GRAY}     mixed-IP hosts stripped: {totals['stripped']}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")