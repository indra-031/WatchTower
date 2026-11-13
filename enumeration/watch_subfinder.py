#!/usr/bin/env python3
"""
WatchTower - Subfinder Module
Runs subfinder on a scope and saves results to:
database/<program-name>/enum-output/subfinder.json

Supports:
  - domain.tld
  - https://domain.tld/
  - http://sub.domain.tld/path
  - *.domain.tld
"""

import sys
import subprocess
import re
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


# =========================
# Paths
# =========================

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_DIR = BASE_DIR / "database"


# =========================
# Imports from configs/
# =========================

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from configs.colors import colors


# =========================
# Helpers
# =========================

def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def extract_domain(raw_input: str) -> str:
    """
    Extract pure domain from any input format.
    Examples:
      https://memoryleaks.ir/  -> memoryleaks.ir
      http://sub.example.com/path -> sub.example.com
      example.com              -> example.com
      *.example.com            -> example.com
    """
    raw_input = raw_input.strip().lstrip("*.")

    if "://" not in raw_input:
        return raw_input.lower().rstrip("/")

    parsed = urlparse(raw_input)
    domain = parsed.hostname

    if not domain:
        match = re.search(r'(?:https?://)?([^/:\s]+)', raw_input)
        if match:
            domain = match.group(1)

    return domain.lower() if domain else raw_input.lower()


def sanitize_name(name: str) -> str:
    """
    Convert program name into safe directory name.
    """
    return (
        name.strip()
        .lower()
        .replace(" ", "-")
        .replace("/", "-")
        .replace("\\", "-")
        .replace(":", "-")
    )


def run_command_in_bash(command):
    try:
        result = subprocess.run(
            ["bash", "-c", command],
            capture_output=True,
            text=True
        )

        if result.returncode != 0:
            print(f"{colors.YELLOW}Error occurred:{colors.RESET} {result.stderr}")
            return False

        return result.stdout.splitlines()
    except subprocess.CalledProcessError as exc:
        print(f"{colors.RED}Status: FAIL{colors.RESET} {exc.returncode} {exc.output}")
        return False


def find_program_by_scope(scope_name: str) -> dict | None:
    """
    Search all program.json files in database/ and find
    the one that has this scope_name in its 'scope' or 'out_of_scope' list.
    Also checks if scope_name is a subdomain of any scope.
    """
    if not DATABASE_DIR.exists():
        print(f"{colors.RED}❌ database/ directory not found{colors.RESET}")
        return None

    for program_dir in DATABASE_DIR.iterdir():
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

        # Prefer new key; fall back to legacy "ooscope".
        scopes = (
            data.get("scope", [])
            + data.get("out_of_scope", data.get("ooscope", []))
        )

        # Direct match
        if scope_name in scopes:
            return data

        # Check if scope_name is subdomain of any scope
        for scope in scopes:
            clean_scope = scope.lstrip("*.").lower()
            if scope_name == clean_scope:
                return data
            if scope_name.endswith("." + clean_scope):
                return data

    return None


def subfinder_enum(domain):
    command = f"subfinder -d {domain} -all"
    print(f"{colors.GRAY}Executing command: {command}{colors.RESET}")
    res = run_command_in_bash(command)

    if res is False:
        return []

    res_num = len(res)
    print(f"{colors.GRAY}done for {domain}, results: {res_num}{colors.RESET}")

    return res


def filter_subdomains(subs: list, domain: str) -> list:
    """
    Filter subdomains that belong to the target domain.
    Matches: *.domain.tld
    """
    pattern = r'\.?\s*' + re.escape(domain) + r'$'
    filtered = []

    for sub in subs:
        sub = sub.strip().lower()
        if not sub:
            continue
        clean_sub = sub.lstrip("*.")
        if re.search(pattern, clean_sub, re.IGNORECASE):
            filtered.append(clean_sub)

    return sorted(list(set(filtered)))


def save_subfinder_output(program_name: str, data: dict):
    """
    Save scan result to:
    database/<program-name>/enum-output/subfinder.json
    """
    safe_name = sanitize_name(program_name)
    output_dir = DATABASE_DIR / safe_name / "enum-output"
    output_file = output_dir / "subfinder.json"

    output_dir.mkdir(parents=True, exist_ok=True)

    # Load existing scans
    existing_data = {"scans": []}
    if output_file.exists():
        try:
            with output_file.open("r", encoding="utf-8") as f:
                existing_data = json.load(f)
        except (json.JSONDecodeError, Exception):
            existing_data = {"scans": []}

    # Append new scan
    existing_data["scans"].append(data)

    # Save
    with output_file.open("w", encoding="utf-8") as f:
        json.dump(existing_data, f, indent=4, ensure_ascii=False)

    print(f"{colors.GREEN}💾 Scan saved to {output_file}{colors.RESET}")


# =========================
# Main
# =========================

if __name__ == "__main__":
    raw_input = sys.argv[1] if len(sys.argv) > 1 else False

    if raw_input is False:
        print(f"Usage: python3 watch_subfinder.py <scope_name | URL>")
        print(f"Examples:")
        print(f"  python3 watch_subfinder.py example.com")
        print(f"  python3 watch_subfinder.py https://example.com/")
        print(f"  python3 watch_subfinder.py http://sub.example.com/path")
        sys.exit(1)

    # Extract clean domain from input
    domain = extract_domain(raw_input)

    if raw_input != domain:
        print(f"{colors.GRAY}Input: {raw_input}{colors.RESET}")
        print(f"{colors.GRAY}Extracted domain: {domain}{colors.RESET}")

    # Find program by scope
    program = find_program_by_scope(domain)

    if program:
        program_name = program.get("program_name", "unknown")
        print(f"{colors.CYAN}[{current_time()}] running Subfinder module for '{domain}'{colors.RESET}")
        print(f"{colors.CYAN}📦 Program: {program_name}{colors.RESET}")

        subs = subfinder_enum(domain)

        if not subs:
            print(f"{colors.YELLOW}[{current_time()}] No results from subfinder for {domain}{colors.RESET}")
            sys.exit(0)

        valid_subs = filter_subdomains(subs, domain)
        print(f"{colors.GRAY}[{current_time()}] Valid subdomains after filter: {len(valid_subs)}{colors.RESET}")

        scan_data = {
            "timestamp": current_time(),
            "domain": domain,
            "program_name": program_name,
            "source": "subfinder",
            "subdomains_count": len(valid_subs),
            "subdomains": valid_subs
        }

        save_subfinder_output(program_name, scan_data)

    else:
        print(f"{colors.RED}[{current_time()}] scope '{domain}' does not exist in watchtower{colors.RESET}")
        print(f"{colors.YELLOW}Make sure a program.json with this scope exists in database/<program>/{colors.RESET}")
        sys.exit(1)