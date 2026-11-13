#!/usr/bin/env python3
"""
WatchTower - Secret : vscan (native)
Regex-based secret scanner. Walks every js/html file and outputs a
single combined JSON.

Writes: database/<program>/secret/vscan/vscan.json
"""

import sys
import re
import json
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


TOOL = "vscan"

PATTERNS = {
    "Username": re.compile(
        r'(?i)\b(user(name)?|login)\b\s*[:=]\s*[\'"]([^\'"]+)[\'"]'
    ),
    "Password": re.compile(
        r'(?i)\b(password|passwd|pwd)\b\s*[:=]\s*[\'"]([^\'"]+)[\'"]'
    ),
    "API Key": re.compile(
        r'(?i)\b(api[_-]?key|apikey)\b\s*[:=]\s*[\'"]([^\'"]+)[\'"]'
    ),
    "AWS Access Key": re.compile(r'\bAKIA[0-9A-Z]{16}\b'),
    "Slack Webhook": re.compile(
        r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+'
    ),
    "JWT": re.compile(r'\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b'),
}


def scan_file(path, base_path):
    findings = []
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except Exception:
        return findings
    for lineno, line in enumerate(lines, start=1):
        for name, regex in PATTERNS.items():
            for match in regex.finditer(line):
                findings.append({
                    "file": str(path.relative_to(base_path)),
                    "type": name,
                    "match": match.group(0),
                    "line_number": lineno,
                    "line_content": line.strip(),
                })
    return findings


def process_program(program):
    pn = program["program_name"]
    pd = program["path"]
    out_dir = pd / "secret" / TOOL

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    all_findings = []
    seen = set()

    for label, src_dir in get_sources(pd):
        if not src_dir.exists():
            continue
        found_here = False
        for f in list(src_dir.rglob("*.js")) + list(src_dir.rglob("*.html")):
            for item in scan_file(f, pd):
                fp = (item["file"], item["line_number"], item["match"])
                if fp in seen:
                    continue
                seen.add(fp)
                all_findings.append(item)
                found_here = True
        if found_here:
            print(f"     {colors.GREEN}✅ {label}{colors.RESET}")
        else:
            print(f"     {colors.GRAY}✗ {label}{colors.RESET}")

    if not all_findings:
        finalize_out_dir(out_dir, False)
        return False

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "vscan.json").write_text(
        json.dumps(all_findings, indent=4), encoding="utf-8",
    )
    print(f"     {colors.GREEN}💾 {len(all_findings)} finding(s) → {out_dir / 'vscan.json'}{colors.RESET}")
    return True


def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — vscan{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_vscan.py <domain>")
            print("       python3 watch_vscan.py --all")
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
    print(f"{colors.GREEN}✅ vscan complete ({hits}/{len(programs)} with findings){colors.RESET}")


if __name__ == "__main__":
    main()