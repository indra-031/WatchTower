#!/usr/bin/env python3
"""
WatchTower - crt.name Module
Fetches subdomains from crt.name Certificate Transparency index.
Saves results to: database/<program-name>/enum-output/crtname.json

API:
  - https://crt.name/v1/search?apex=<domain>&format=json
  - No API key required, rate limit: 100 requests/day per IP
"""

import sys
import re
import json
import requests
from datetime import datetime
from pathlib import Path


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


def sanitize_name(name: str) -> str:
    return (
        name.strip()
        .lower()
        .replace(" ", "-")
        .replace("/", "-")
        .replace("\\", "-")
        .replace(":", "-")
    )


def find_program_by_scope(scope_name: str) -> dict | None:
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

        if scope_name in scopes:
            return data

        for scope in scopes:
            clean_scope = scope.lstrip("*.").lower()
            if scope_name == clean_scope:
                return data
            if scope_name.endswith("." + clean_scope):
                return data

    return None


def crtname_enum(domain: str) -> list:
    """
    Query crt.name API and return list of subdomains.
    """
    url = f"https://crt.name/v1/search?apex={domain}&format=json"
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
        ),
        "Accept": "application/json",
    }

    print(f"{colors.GRAY}Requesting: {url}{colors.RESET}")

    try:
        response = requests.get(url, headers=headers, timeout=30)

        if response.status_code == 429:
            print(f"{colors.YELLOW}⚠️ Rate limit hit (429). crt.name allows 100 requests/day.{colors.RESET}")
            return []

        if response.status_code != 200:
            print(f"{colors.YELLOW}Error: {response.status_code} - {response.reason}{colors.RESET}")
            return []

        data = response.json()

        subdomains = []
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    sub = item.get("sub", "").strip().lower()
                elif isinstance(item, str):
                    sub = item.strip().lower()
                else:
                    continue
                if sub:
                    subdomains.append(sub)

        subdomains = sorted(list(set(subdomains)))
        print(f"{colors.GRAY}Done for {domain}, results: {len(subdomains)}{colors.RESET}")
        return subdomains

    except requests.Timeout:
        print(f"{colors.YELLOW}⏰ Timeout for {domain}{colors.RESET}")
        return []
    except requests.ConnectionError:
        print(f"{colors.RED}❌ Connection error for {domain}{colors.RESET}")
        return []
    except Exception as e:
        print(f"{colors.RED}❌ Error: {e}{colors.RESET}")
        return []


def filter_subdomains(subs: list, domain: str) -> list:
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


def save_output(program_name: str, data: dict):
    safe_name = sanitize_name(program_name)
    output_dir = DATABASE_DIR / safe_name / "enum-output"
    output_file = output_dir / "crtname.json"

    output_dir.mkdir(parents=True, exist_ok=True)

    existing_data = {"scans": []}
    if output_file.exists():
        try:
            with output_file.open("r", encoding="utf-8") as f:
                existing_data = json.load(f)
        except (json.JSONDecodeError, Exception):
            existing_data = {"scans": []}

    existing_data["scans"].append(data)

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(existing_data, f, indent=4, ensure_ascii=False)

    print(f"{colors.GREEN}💾 Scan saved to {output_file}{colors.RESET}")


# =========================
# Main
# =========================

if __name__ == "__main__":
    raw_input = sys.argv[1] if len(sys.argv) > 1 else False

    if raw_input is False:
        print(f"Usage: python3 watch_crtname.py <domain>")
        print(f"Example: python3 watch_crtname.py example.com")
        sys.exit(1)

    domain = raw_input.strip().lower().lstrip("*.")

    program = find_program_by_scope(domain)

    if not program:
        print(f"{colors.RED}[{current_time()}] scope '{domain}' does not exist in watchtower{colors.RESET}")
        print(f"{colors.YELLOW}Make sure a program.json with this scope exists in database/<program>/{colors.RESET}")
        sys.exit(1)

    program_name = program.get("program_name", "unknown")
    print(f"{colors.CYAN}[{current_time()}] running crt.name module for '{domain}'{colors.RESET}")
    print(f"{colors.CYAN}📦 Program: {program_name}{colors.RESET}")

    subs = crtname_enum(domain)

    if not subs:
        print(f"{colors.YELLOW}[{current_time()}] No results from crt.name for {domain}{colors.RESET}")
        sys.exit(0)

    valid_subs = filter_subdomains(subs, domain)
    print(f"{colors.GRAY}[{current_time()}] Valid subdomains after filter: {len(valid_subs)}{colors.RESET}")

    scan_data = {
        "timestamp": current_time(),
        "domain": domain,
        "program_name": program_name,
        "source": "crtname",
        "subdomains_count": len(valid_subs),
        "subdomains": valid_subs,
    }

    save_output(program_name, scan_data)