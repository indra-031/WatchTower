#!/usr/bin/env python3
"""
WatchTower - Pattern Recognition (All Programs)
Runs pattern recognition on all programs that have subdomains in
database/<program>/enum-output/all-subdomains.json.

Reads:
  database/<program>/enum-output/all-subdomains.json
  database/<program>/enum-output/pattern_done.json
Writes:
  database/<program>/enum-output/pattern-recognition.json
  database/<program>/enum-output/pattern_done.json
  database/<program>/enum-output/all-subdomains.json
  database/<program>/dns/lives.json
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

from watch_pattern_recognition import (
    main_for_program,
    get_programs_with_subdomains,
    current_time,
    DATABASE_DIR,
)


# =========================
# Imports from configs/
# =========================

PROJECT_ROOT = SCRIPT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from configs.colors import colors


# =========================
# Main
# =========================

if __name__ == "__main__":
    print(f"{colors.CYAN}[{current_time()}] WatchTower — Pattern Recognition (All){colors.RESET}\n")

    programs = get_programs_with_subdomains()
    if not programs:
        print(f"{colors.RED}❌ No programs with subdomains found.{colors.RESET}")
        print(f"{colors.YELLOW}   Run watch_enum_all.py first to generate all-subdomains.json.{colors.RESET}")
        sys.exit(1)

    print(f"{colors.CYAN}📦 Programs with subdomains: {len(programs)}{colors.RESET}\n")

    total_success = 0
    total_new = 0

    for idx, prog in enumerate(programs, 1):
        print(f"{colors.BLUE}{'='*60}{colors.RESET}")
        print(f"{colors.BLUE}[{idx}/{len(programs)}] {prog['program_name']} — {prog['domain']}{colors.RESET}")
        print(f"{colors.BLUE}   Known subdomains: {len(prog['subdomains'])}{colors.RESET}")
        print(f"{colors.BLUE}{'='*60}{colors.RESET}")

        try:
            new_live = main_for_program(prog)
            if new_live:
                total_success += 1
                total_new += len(new_live)
            print()
        except Exception as e:
            print(f"{colors.RED}❌ Error on {prog['program_name']}: {e}{colors.RESET}\n")

    # Final summary
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ Pattern Recognition completed{colors.RESET}")
    print(f"{colors.GREEN}   Programs with new findings : {total_success}/{len(programs)}{colors.RESET}")
    print(f"{colors.GREEN}   Total new live subdomains  : {total_new}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")