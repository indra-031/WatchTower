#!/usr/bin/env python3
"""
WatchTower - DNS Static Brute-force (All Programs)
Skips domains already recorded in database/<program>/dns/static_brute_done.json.

Reads:
  database/<program>/program.json
  dns/brute-files/*.txt
  database/<program>/dns/static_brute_done.json
Writes:
  database/<program>/dns/nsbrute.json
  database/<program>/dns/lives.json
  database/<program>/dns/static_brute_done.json
  database/<program>/enum-output/all-subdomains.json
"""

import sys
import json
import time
from pathlib import Path
from datetime import datetime


# =========================
# Local module import
# =========================

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from watch_static_dns_brute import (
    ns_brute_static,
    save_results,
    extract_domain,
    current_time,
    load_done,
    DATABASE_DIR,
)


# =========================
# Imports from configs/
# =========================
# Importing watch_static_ns_brute already put BASE_DIR on sys.path.

from configs.colors import colors


# =========================
# Config
# =========================

FORCE = "--force" in sys.argv


# =========================
# Helpers
# =========================

def get_all_programs():
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
        except Exception:
            continue
        scopes = [s.strip() for s in data.get("scope", []) if s and s.strip()]
        if not scopes:
            continue
        programs.append({
            "program_name": data.get("program_name", program_dir.name),
            "scopes": scopes,
        })
    return programs


def format_elapsed(seconds: float) -> str:
    """Human-readable elapsed time."""
    total = int(seconds)
    h, rem = divmod(total, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m {s}s"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


# =========================
# Main
# =========================

if __name__ == "__main__":
    start_time = time.time()
    print(f"{colors.CYAN}[{current_time()}] WatchTower — Static Brute-force (All){colors.RESET}\n")

    programs = get_all_programs()
    if not programs:
        print(f"{colors.RED}❌ No programs found in database/{colors.RESET}")
        print(f"{colors.YELLOW}   Run programs/watch_sync_programs.py first.{colors.RESET}")
        sys.exit(1)

    total_scopes = sum(len(p["scopes"]) for p in programs)

    # Aggregate done counts
    total_done_before = 0
    for program in programs:
        total_done_before += len(load_done(program["program_name"]))

    print(f"{colors.CYAN}📦 Programs : {len(programs)}{colors.RESET}")
    print(f"{colors.CYAN}🎯 Scopes   : {total_scopes}{colors.RESET}")
    if total_done_before:
        print(f"{colors.CYAN}✅ Already done: {total_done_before} domain(s){colors.RESET}")
    if FORCE:
        print(f"{colors.YELLOW}⚡ FORCE mode — ignoring done-files{colors.RESET}")
    print()

    total_success = 0       # found at least 1 subdomain
    total_skipped = 0       # already in done-file
    total_empty = 0         # ran but returned 0 subdomains
    total_failed = 0        # exception or fatal error

    for program in programs:
        program_name = program["program_name"]
        scopes = program["scopes"]

        print(f"{colors.BLUE}{'='*60}{colors.RESET}")
        print(f"{colors.BLUE}🎯 {program_name} — {len(scopes)} scope(s){colors.RESET}")
        print(f"{colors.BLUE}{'='*60}{colors.RESET}")

        for i, scope in enumerate(scopes, 1):
            print(f"\n{colors.CYAN}[{i}/{len(scopes)}] {scope}{colors.RESET}")

            domain = extract_domain(scope)
            scope_start = time.time()

            try:
                subs = ns_brute_static(domain, program_name, force=FORCE)

                if subs is None:
                    total_skipped += 1
                    print(f"{colors.GRAY}   ⏭  {domain} — already done{colors.RESET}")
                    continue

                if subs:
                    save_results(program_name, domain, subs)
                    total_success += 1
                else:
                    total_empty += 1
                    print(f"{colors.YELLOW}⚠️ No subdomains found for {domain}{colors.RESET}")

                elapsed = format_elapsed(time.time() - scope_start)
                print(f"{colors.GRAY}   ⏱  {elapsed}{colors.RESET}")

            except KeyboardInterrupt:
                print(f"\n{colors.YELLOW}⚠️ Interrupted by user — stopping pipeline{colors.RESET}")
                sys.exit(130)
            except Exception as e:
                total_failed += 1
                print(f"{colors.RED}❌ Error on {domain}: {e}{colors.RESET}")

        print()

    # Final summary
    total_elapsed = format_elapsed(time.time() - start_time)

    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ Static Brute-force completed{colors.RESET}")
    print(f"{colors.GREEN}   Programs : {len(programs)}{colors.RESET}")
    print(f"{colors.GREEN}   Scopes   : {total_scopes}{colors.RESET}")
    print(f"{colors.GREEN}   Success  : {total_success} (new subs found){colors.RESET}")
    if total_skipped:
        print(f"{colors.CYAN}   Skipped  : {total_skipped} (already done){colors.RESET}")
    if total_empty:
        print(f"{colors.YELLOW}   Empty    : {total_empty} (ran, 0 results){colors.RESET}")
    if total_failed:
        print(f"{colors.RED}   Failed   : {total_failed}{colors.RESET}")
    print(f"{colors.CYAN}   Elapsed  : {total_elapsed}{colors.RESET}")
    print(f"{colors.GRAY}   Done files: database/<program>/dns/static_brute_done.json{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")