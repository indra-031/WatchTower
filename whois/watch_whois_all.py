#!/usr/bin/env python3
"""
WatchTower - WHOIS / RDAP (All Programs)
Runs RDAP lookups on every program in database/.
Skips targets already recorded in whois/whois_done.json (unless --force).

Reads:  database/<program>/program.json
        database/<program>/dns/lives.json
        database/<program>/http/lives-http.json
        database/<program>/whois/whois_done.json
Writes: database/<program>/whois/whois.json
        database/<program>/whois/lives-whois.json
        database/<program>/whois/whois_done.json

Usage:
  python3 watch_whois_all.py
  python3 watch_whois_all.py --force
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

from watch_whois import (
    collect_targets,
    query_domain,
    query_ip,
    save_results,
    load_done,
    save_done,
    mark_done_in_memory,
    target_key,
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
# Helpers
# =========================

def get_all_programs():
    if not DATABASE_DIR.exists():
        return []
    programs = []
    for program_dir in sorted(DATABASE_DIR.iterdir()):
        if not program_dir.is_dir():
            continue
        if program_dir.name.startswith("_"):
            continue
        program_file = program_dir / "program.json"
        if not program_file.exists():
            continue
        try:
            data = json.loads(program_file.read_text())
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


# =========================
# Main
# =========================

if __name__ == "__main__":
    force = "--force" in sys.argv

    print(f"{colors.CYAN}[{current_time()}] WatchTower — WHOIS/RDAP (All){colors.RESET}\n")

    programs = get_all_programs()
    if not programs:
        print(f"{colors.RED}❌ No programs found in database/{colors.RESET}")
        print(f"{colors.YELLOW}   Run programs/watch_sync_programs.py first.{colors.RESET}")
        sys.exit(1)

    total_scopes = sum(len(p["scopes"]) for p in programs)

    print(f"{colors.CYAN}📦 Programs : {len(programs)}{colors.RESET}")
    print(f"{colors.CYAN}🎯 Scopes   : {total_scopes}{colors.RESET}")
    if force:
        print(f"{colors.YELLOW}⚡ FORCE mode — ignoring done-file{colors.RESET}")
    print()

    total_targets = 0        # targets actually queried
    total_results = 0        # targets that returned data
    total_no_data = 0        # targets that returned 404
    total_errors = 0         # targets that errored (not marked done)
    total_skipped = 0        # targets skipped as already done

    for program in programs:
        program_name = program["program_name"]
        scopes = program["scopes"]

        done = load_done(program_name)

        print(f"{colors.BLUE}{'='*60}{colors.RESET}")
        print(f"{colors.BLUE}🎯 {program_name} — {len(scopes)} scope(s){colors.RESET}")
        print(f"{colors.BLUE}{'='*60}{colors.RESET}")

        seen_in_run = set()

        for i, scope in enumerate(scopes, 1):
            clean_scope = scope.strip().lstrip("*.").lower()
            print(f"\n{colors.CYAN}[{i}/{len(scopes)}] {clean_scope}{colors.RESET}")

            targets = collect_targets(program_name, clean_scope)
            if not targets:
                print(f"{colors.YELLOW}⚠️ No targets for {clean_scope}{colors.RESET}")
                continue

            # Dedupe across scopes within this run
            targets = [(t, v) for t, v in targets if (t, v) not in seen_in_run]

            # Filter by done (unless force)
            if not force:
                original = len(targets)
                targets = [
                    (t, v) for t, v in targets
                    if target_key(t, v) not in done
                ]
                skipped = original - len(targets)
                if skipped:
                    total_skipped += skipped
                    print(f"     {colors.GRAY}⏭  {skipped} already queried, "
                          f"{len(targets)} pending{colors.RESET}")
                if not targets:
                    print(f"     {colors.GREEN}✅ All targets already queried{colors.RESET}")
                    continue

            domain_count = sum(1 for t, _ in targets if t == "domain")
            ip_count = sum(1 for t, _ in targets if t == "ip")
            print(f"     {colors.CYAN}📋 {len(targets)} target(s) "
                  f"({domain_count} domains, {ip_count} IPs){colors.RESET}")

            results = []
            for j, (ttype, value) in enumerate(targets, 1):
                seen_in_run.add((ttype, value))
                print(f"     {colors.GRAY}[{j}/{len(targets)}] {ttype}: {value}{colors.RESET}")

                if ttype == "domain":
                    res, status = query_domain(value)
                else:
                    res, status = query_ip(value)

                total_targets += 1

                if status == "ok" and res:
                    results.append(res)
                    total_results += 1
                    mark_done_in_memory(done, ttype, value, "ok")
                    if ttype == "domain":
                        print(f"       {colors.GREEN}✅ registrar: "
                              f"{res.get('registrar') or 'N/A'}{colors.RESET}")
                    else:
                        print(f"       {colors.GREEN}✅ {res.get('name') or 'N/A'} | "
                              f"ASN: {res.get('asn') or 'N/A'}{colors.RESET}")
                elif status == "not_found":
                    total_no_data += 1
                    mark_done_in_memory(done, ttype, value, "not_found")
                    print(f"       {colors.YELLOW}⚠️ not_found{colors.RESET}")
                else:
                    total_errors += 1
                    print(f"       {colors.RED}❌ error (will retry){colors.RESET}")

            if results:
                save_results(program_name, clean_scope, results)

        save_done(program_name, done)
        print()

    # Final summary
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ WHOIS/RDAP complete{colors.RESET}")
    print(f"{colors.GREEN}   Programs     : {len(programs)}{colors.RESET}")
    print(f"{colors.GREEN}   Scopes       : {total_scopes}{colors.RESET}")
    print(f"{colors.GREEN}   Queried      : {total_targets}{colors.RESET}")
    print(f"{colors.GREEN}   With data    : {total_results}{colors.RESET}")
    if total_no_data:
        print(f"{colors.YELLOW}   Not found    : {total_no_data}{colors.RESET}")
    if total_errors:
        print(f"{colors.RED}   Errors       : {total_errors}{colors.RESET}")
    if total_skipped:
        print(f"{colors.CYAN}   Skipped      : {total_skipped} (already done){colors.RESET}")
    print(f"{colors.GRAY}   Done files: database/<program>/whois/whois_done.json{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")