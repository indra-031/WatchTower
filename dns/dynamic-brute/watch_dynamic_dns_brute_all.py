#!/usr/bin/env python3
"""
WatchTower - Dynamic DNS Brute-force (All Programs)
Runs dnsgen-based dynamic brute-force on all scopes of all programs.

Reads:
  database/<program>/program.json  ->  scope list
  database/<program>/dns/lives.json ->  known subdomains
Writes:
  database/<program>/dns/nsbrute.json
  database/<program>/dns/lives.json
  database/<program>/enum-output/all-subdomains.json
"""

import sys
import json
from pathlib import Path


# =========================
# Local module import
# =========================

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from watch_dynamic_dns_brute import (
    dynamic_brute,
    save_results,
    extract_domain,
    current_time,
    DATABASE_DIR,
    BASE_DIR,
)


# =========================
# Imports from configs/
# =========================

from configs.colors import colors


# =========================
# Helpers
# =========================

def get_all_programs() -> list:
    if not DATABASE_DIR.exists():
        return []
    programs = []
    for program_dir in sorted(DATABASE_DIR.iterdir()):
        if not program_dir.is_dir():
            continue
        program_file = program_dir / "program.json"
        if not program_file.exists():
            continue
        try:
            with program_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, Exception):
            continue
        scopes = [s.strip() for s in data.get("scope", []) if s and s.strip()]
        if not scopes:
            continue
        programs.append({
            "program_name": data.get("program_name", program_dir.name),
            "scopes": scopes,
        })
    return programs


# =========================
# Main
# =========================

if __name__ == "__main__":
    print(f"{colors.CYAN}[{current_time()}] WatchTower — Dynamic Brute-force (All){colors.RESET}\n")

    programs = get_all_programs()
    if not programs:
        print(f"{colors.RED}❌ No programs found in database/{colors.RESET}")
        print(f"{colors.YELLOW}   Run programs/watch_sync_programs.py first.{colors.RESET}")
        sys.exit(1)

    total_scopes = sum(len(p["scopes"]) for p in programs)

    print(f"{colors.CYAN}📦 Programs : {len(programs)}{colors.RESET}")
    print(f"{colors.CYAN}🎯 Scopes   : {total_scopes}{colors.RESET}")
    print()

    total_success = 0
    total_new = 0
    total_fail = 0

    for program in programs:
        program_name = program["program_name"]
        scopes = program["scopes"]

        print(f"{colors.BLUE}{'='*60}{colors.RESET}")
        print(f"{colors.BLUE}🎯 {program_name} — {len(scopes)} scope(s){colors.RESET}")
        print(f"{colors.BLUE}{'='*60}{colors.RESET}")

        for i, scope in enumerate(scopes, 1):
            print(f"\n{colors.CYAN}[{i}/{len(scopes)}] {scope}{colors.RESET}")

            domain = extract_domain(scope)

            try:
                new_live = dynamic_brute(domain, program_name)
                if new_live:
                    save_results(program_name, domain, new_live)
                    total_success += 1
                    total_new += len(new_live)
                else:
                    print(f"{colors.YELLOW}⚠️ No new subdomains for {domain}{colors.RESET}")
                    total_fail += 1
            except Exception as e:
                print(f"{colors.RED}❌ Error on {domain}: {e}{colors.RESET}")
                total_fail += 1

        print()

    # Final summary
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ Dynamic Brute-force completed{colors.RESET}")
    print(f"{colors.GREEN}   Programs : {len(programs)}{colors.RESET}")
    print(f"{colors.GREEN}   Scopes   : {total_scopes}{colors.RESET}")
    print(f"{colors.GREEN}   Success  : {total_success}{colors.RESET}")
    print(f"{colors.GREEN}   New subs : {total_new}{colors.RESET}")
    if total_fail:
        print(f"{colors.YELLOW}   Failed   : {total_fail}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")