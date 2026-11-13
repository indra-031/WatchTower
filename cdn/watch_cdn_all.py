#!/usr/bin/env python3
"""
WatchTower - CDN / Cloud / WAF Detection (All Programs)
Runs cdncheck-based detection on all HTTP hosts of all programs.

Reads:
  database/<program>/program.json
  database/<program>/dns/lives.json
Writes:
  database/<program>/cdn/cdn.json
  database/<program>/cdn/lives-cdn.json
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

from watch_cdn import (
    detect_cdn,
    save_cdn_results,
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
    print(f"{colors.CYAN}[{current_time()}] WatchTower — CDN Detection (All){colors.RESET}\n")

    programs = get_all_programs()
    if not programs:
        print(f"{colors.RED}❌ No programs found in database/{colors.RESET}")
        sys.exit(1)

    total_scopes = sum(len(p["scopes"]) for p in programs)

    print(f"{colors.CYAN}📦 Programs : {len(programs)}{colors.RESET}")
    print(f"{colors.CYAN}🎯 Scopes   : {total_scopes}{colors.RESET}\n")

    total_hosts = 0
    total_proxied = 0
    total_success = 0
    total_fail = 0

    for program in programs:
        program_name = program["program_name"]
        scopes = program["scopes"]

        print(f"{colors.BLUE}{'='*60}{colors.RESET}")
        print(f"{colors.BLUE}🎯 {program_name} — {len(scopes)} scope(s){colors.RESET}")
        print(f"{colors.BLUE}{'='*60}{colors.RESET}")

        for i, scope in enumerate(scopes, 1):
            print(f"\n{colors.CYAN}[{i}/{len(scopes)}] {scope}{colors.RESET}")

            try:
                results = detect_cdn(program_name, scope)
                if not results:
                    print(f"{colors.YELLOW}⚠️ No hosts for {scope}{colors.RESET}")
                    total_fail += 1
                    continue

                for r in results:
                    if r["cdn"]:
                        tag = f"{colors.YELLOW}Proxied: {r['provider']}{colors.RESET}"
                    else:
                        tag = f"{colors.GREEN}Direct{colors.RESET}"
                    print(f"     {r['host']:40s} {tag}")

                proxied = sum(1 for r in results if r["cdn"])
                total_hosts += len(results)
                total_proxied += proxied
                total_success += 1

                save_cdn_results(program_name, scope, results)
            except Exception as e:
                print(f"{colors.RED}❌ Error on {scope}: {e}{colors.RESET}")
                total_fail += 1

        print()

    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ CDN detection completed{colors.RESET}")
    print(f"{colors.GREEN}   Programs : {len(programs)}{colors.RESET}")
    print(f"{colors.GREEN}   Scopes   : {total_scopes}{colors.RESET}")
    print(f"{colors.GREEN}   Success  : {total_success}{colors.RESET}")
    print(f"{colors.GREEN}   Hosts    : {total_hosts}{colors.RESET}")
    print(f"{colors.YELLOW}   Proxied  : {total_proxied}{colors.RESET}")
    if total_fail:
        print(f"{colors.YELLOW}   Failed   : {total_fail}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")