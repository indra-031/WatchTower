#!/usr/bin/env python3
"""
WatchTower - Wildcard DNS Test (All Programs)
Runs wildcard DNS detection on all scopes of all programs found in database/.

Skips domains already recorded in dns/wildcard_done.json (unless --force).

Reads:
  database/<program>/program.json
  database/<program>/dns/wildcard_done.json
Writes:
  database/<program>/dns/wildcard-test.json
  database/<program>/dns/wildcard_done.json

Usage:
  python3 watch_wildcard_ns_test_all.py
  python3 watch_wildcard_ns_test_all.py --force
"""

import sys
import json
import threading
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


# =========================
# Local module import
# =========================

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from watch_wildcard_dns_test import (
    wildcard_test,
    save_output,
    load_done,
    mark_done,
    current_time,
    DATABASE_DIR,
    BASE_DIR,
    WILDCARD_PROBE_STRING,
)


# =========================
# Imports from configs/
# =========================

from configs.colors import colors


# =========================
# Configuration
# =========================

PARALLEL = True
MAX_WORKERS = 5


# =========================
# Helpers
# =========================

def get_all_programs():
    if not DATABASE_DIR.exists():
        return []

    programs = []
    for program_dir in sorted(DATABASE_DIR.iterdir()):
        if not program_dir.is_dir() or program_dir.name.startswith("_"):
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


def process_scope(scope, program_name, save_lock):
    """
    Returns one of: "wildcard", "clean", "skipped", "failed".
    """
    domain = scope.strip().lower().lstrip("*.")
    print(f"\n{colors.CYAN}[{current_time()}] Testing {domain} ({program_name}){colors.RESET}")

    try:
        result = wildcard_test(domain)
    except Exception as e:
        print(f"{colors.RED}❌ Error on {domain}: {e}{colors.RESET}")
        return "failed"

    if result["wildcard_detected"]:
        print(f"{colors.YELLOW}  ⚠️  WILDCARD DETECTED — IPs: "
              f"{', '.join(result['wildcard_ips'])}{colors.RESET}")
    else:
        print(f"{colors.GREEN}  ✅ No wildcard (safe for brute force){colors.RESET}")

    scan_data = {
        "timestamp": current_time(),
        "domain": domain,
        "program_name": program_name,
        "source": "wildcard-test",
        **result,
    }

    with save_lock:
        save_output(program_name, scan_data)
        mark_done(program_name, domain, result["wildcard_detected"])

    return "wildcard" if result["wildcard_detected"] else "clean"


# =========================
# Main
# =========================

if __name__ == "__main__":
    force = "--force" in sys.argv

    print(f"{colors.CYAN}[{current_time()}] WatchTower — Wildcard Test All{colors.RESET}\n")

    programs = get_all_programs()
    if not programs:
        print(f"{colors.RED}❌ No programs found in database/{colors.RESET}")
        print(f"{colors.YELLOW}   Run programs/watch_sync_programs.py first.{colors.RESET}")
        sys.exit(1)

    total_scopes = sum(len(p["scopes"]) for p in programs)

    print(f"{colors.CYAN}📦 Programs : {len(programs)}{colors.RESET}")
    print(f"{colors.CYAN}🎯 Scopes   : {total_scopes}{colors.RESET}")
    print(f"{colors.CYAN}🧪 Probe    : {WILDCARD_PROBE_STRING[:24]}...{colors.RESET}")
    print(f"{colors.CYAN}⚡ Mode     : {'Parallel' if PARALLEL else 'Sequential'}{colors.RESET}")
    if PARALLEL:
        print(f"{colors.CYAN}   Workers : {MAX_WORKERS}{colors.RESET}")
    if force:
        print(f"{colors.YELLOW}⚡ FORCE mode — ignoring done-file{colors.RESET}")
    print()

    save_lock = threading.Lock()
    total_wildcard = 0
    total_clean = 0
    total_skipped = 0
    total_failed = 0
    lock = threading.Lock()

    for program in programs:
        program_name = program["program_name"]
        scopes = program["scopes"]

        done = load_done(program_name)

        # Filter by done (unless force)
        if not force:
            pending = []
            for s in scopes:
                clean = s.strip().lower().lstrip("*.")
                if clean in done:
                    total_skipped += 1
                else:
                    pending.append(s)
        else:
            pending = scopes

        print(f"{colors.BLUE}{'='*60}{colors.RESET}")
        print(f"{colors.BLUE}🎯 {program_name} — {len(scopes)} scope(s) "
              f"({len(pending)} pending){colors.RESET}")
        print(f"{colors.BLUE}{'='*60}{colors.RESET}")

        if not pending:
            print(f"{colors.GREEN}✅ All scopes already tested{colors.RESET}\n")
            continue

        if PARALLEL and len(pending) > 1:
            with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(pending))) as executor:
                futures = {
                    executor.submit(process_scope, scope, program_name, save_lock): scope
                    for scope in pending
                }
                for future in as_completed(futures):
                    scope = futures[future]
                    try:
                        status = future.result()
                        with lock:
                            if status == "wildcard":
                                total_wildcard += 1
                            elif status == "clean":
                                total_clean += 1
                            elif status == "failed":
                                total_failed += 1
                    except Exception as e:
                        print(f"{colors.RED}❌ Thread error on {scope}: {e}{colors.RESET}")
                        with lock:
                            total_failed += 1
        else:
            for i, scope in enumerate(pending, 1):
                print(f"\n{colors.CYAN}[{i}/{len(pending)}] {scope}{colors.RESET}")
                status = process_scope(scope, program_name, save_lock)
                if status == "wildcard":
                    total_wildcard += 1
                elif status == "clean":
                    total_clean += 1
                elif status == "failed":
                    total_failed += 1

        print()

    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ Wildcard Test completed{colors.RESET}")
    print(f"{colors.GREEN}   Programs    : {len(programs)}{colors.RESET}")
    print(f"{colors.GREEN}   Scopes      : {total_scopes}{colors.RESET}")
    print(f"{colors.YELLOW}   ⚠️ Wildcard : {total_wildcard}{colors.RESET}")
    print(f"{colors.GREEN}   ✅ Clean    : {total_clean}{colors.RESET}")
    if total_skipped:
        print(f"{colors.CYAN}   ⏭  Skipped : {total_skipped} (already done){colors.RESET}")
    if total_failed:
        print(f"{colors.RED}   ❌ Failed   : {total_failed}{colors.RESET}")
    print(f"{colors.GRAY}   Done files: database/<program>/dns/wildcard_done.json{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")