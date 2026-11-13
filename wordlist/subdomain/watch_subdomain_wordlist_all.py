#!/usr/bin/env python3
"""
WatchTower - Subdomain Wordlist Enhancer (all programs)

Aggregates word combinations from all programs first, then merges
once into the shared subdomain wordlist.

Writes:
  wordlist/subdomain/custom-subdomain.txt
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

from watch_subdomain_wordlist import (
    current_time,
    collect_words_from_program,
    filter_words,
    merge_into,
    SUB_WORDLIST,
    DATABASE_DIR,
)


# =========================
# Imports from configs/
# =========================

PROJECT_ROOT = SCRIPT_DIR.parent.parent
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


# =========================
# Main
# =========================

if __name__ == "__main__":
    print(f"{colors.CYAN}[{current_time()}] Subdomain Wordlist Enhancer (All Programs){colors.RESET}\n")

    programs = get_all_programs()
    if not programs:
        print(f"{colors.RED}❌ No programs found in database/{colors.RESET}")
        print(f"{colors.YELLOW}   Run programs/watch_sync_programs.py first.{colors.RESET}")
        sys.exit(1)

    print(f"{colors.CYAN}📦 Programs: {len(programs)}{colors.RESET}\n")

    all_words = set()
    total_subs = 0

    for prog in programs:
        pn = prog["program_name"]
        scopes = prog["scopes"]
        base_domains = [s.strip().lstrip("*.").lower() for s in scopes if s and s.strip()]

        words, sub_count = collect_words_from_program(pn, base_domains)
        all_words.update(words)
        total_subs += sub_count

        print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
        print(f"   {colors.GRAY}scopes: {', '.join(base_domains)}{colors.RESET}")
        print(f"   {colors.CYAN}subdomains: {sub_count}  |  raw words: {len(words)}{colors.RESET}")

    print()

    filtered = filter_words(all_words)

    if not filtered:
        print(f"{colors.YELLOW}⚠️ No words extracted — nothing to write.{colors.RESET}")
        sys.exit(0)

    print(f"{colors.CYAN}📊 Aggregate:{colors.RESET}")
    print(f"   {colors.CYAN}total subdomains : {total_subs}{colors.RESET}")
    print(f"   {colors.CYAN}unique words     : {len(filtered)} (after filter){colors.RESET}")
    print()

    stats = merge_into(SUB_WORDLIST, filtered)

    print(f"{colors.GREEN}📁 wordlist/subdomain/custom-subdomain.txt{colors.RESET}")
    print(f"   {colors.GRAY}🆕 +{stats['new_added']} new{colors.RESET}  "
          f"{colors.CYAN}📋 total: {stats['total']}{colors.RESET}  "
          f"{colors.GRAY}(was {stats['existing']}){colors.RESET}")

    print()
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ Subdomain wordlist enhancement complete{colors.RESET}")
    print(f"{colors.GREEN}   Programs       : {len(programs)}{colors.RESET}")
    print(f"{colors.GREEN}   Subdomains     : {total_subs}{colors.RESET}")
    print(f"{colors.GREEN}   Unique words   : {len(filtered)}{colors.RESET}")
    print(f"{colors.GREEN}   New added      : +{stats['new_added']}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")