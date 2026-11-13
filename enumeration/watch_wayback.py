#!/usr/bin/env python3
"""
WatchTower - Wayback Machine Module
Fetches subdomains from web.archive.org (Wayback Machine).
Saves results to: database/<program-name>/enum-output/wayback.json

Supports:
  - domain.tld
  - https://domain.tld/
"""

import sys
import re
import json
import requests
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


def find_program_by_scope(scope_name: str) -> dict | None:
    """
    Search all program.json files in database/ for matching scope.
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

        if scope_name in scopes:
            return data

        for scope in scopes:
            clean_scope = scope.lstrip("*.").lower()
            if scope_name == clean_scope:
                return data
            if scope_name.endswith("." + clean_scope):
                return data

    return None


def wayback_enum(domain: str) -> list:
    """
    Fetch URLs from Wayback Machine and extract subdomains.
    Uses web.archive.org CDX API.
    Returns list of unique subdomains.
    """
    # Wayback CDX API - returns all captured URLs
    url = f"https://web.archive.org/cdx/search/cdx"

    params = {
        "url": f"*.{domain}/*",
        "output": "json",
        "fl": "original",
        "collapse": "urlkey",
        "limit": 100000,
        "filter": "statuscode:200",
    }

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
        ),
    }

    print(f"{colors.GRAY}Requesting: Wayback Machine for *.{domain}{colors.RESET}")

    try:
        response = requests.get(url, params=params, headers=headers, timeout=450)

        if response.status_code != 200:
            print(f"{colors.YELLOW}Error: {response.status_code}{colors.RESET}")
            return []

        data = response.json()

        if not data or len(data) < 2:
            print(f"{colors.YELLOW}No results from Wayback Machine{colors.RESET}")
            return []

        # First row is header ["original"], skip it
        subdomains = set()

        for row in data[1:]:
            if not row or not row[0]:
                continue

            url_str = row[0].strip().lower()

            # Skip if empty
            if not url_str:
                continue

            # Extract hostname from URL
            try:
                # Add scheme if missing
                if "://" not in url_str:
                    url_str = f"http://{url_str}"

                parsed = urlparse(url_str)
                hostname = parsed.hostname

                if hostname and domain in hostname:
                    # Only keep subdomains (not the main domain itself)
                    if hostname != domain and hostname.endswith(f".{domain}"):
                        subdomains.add(hostname)
                    elif hostname == domain:
                        # Also add the main domain with www if it exists
                        pass
            except Exception:
                continue

        subdomains = sorted(list(subdomains))
        print(f"{colors.GRAY}Done for {domain}, results: {len(subdomains)}{colors.RESET}")

        return subdomains

    except requests.Timeout:
        print(f"{colors.YELLOW}⏰ Timeout for {domain}{colors.RESET}")
        return []
    except requests.ConnectionError:
        print(f"{colors.RED}❌ Connection error{colors.RESET}")
        return []
    except json.JSONDecodeError:
        print(f"{colors.YELLOW}⚠️ Invalid JSON response{colors.RESET}")
        return []
    except Exception as e:
        print(f"{colors.RED}❌ Error: {e}{colors.RESET}")
        return []


def filter_subdomains(subs: list, domain: str) -> list:
    """
    Filter subdomains that belong to the target domain.
    Removes wildcards and duplicates.
    """
    pattern = r'\.?\s*' + re.escape(domain) + r'$'
    filtered = []

    for sub in subs:
        sub = sub.strip().lower()
        if not sub:
            continue
        if '*' in sub:
            continue
        clean_sub = sub.lstrip("*.")
        if re.search(pattern, clean_sub, re.IGNORECASE):
            filtered.append(clean_sub)

    return sorted(list(set(filtered)))


def save_wayback_output(program_name: str, data: dict):
    """
    Save scan result to:
    database/<program-name>/enum-output/wayback.json
    """
    safe_name = sanitize_name(program_name)
    output_dir = DATABASE_DIR / safe_name / "enum-output"
    output_file = output_dir / "wayback.json"

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
        print(f"Usage: python3 watch_wayback.py <scope_name | URL>")
        print(f"Examples:")
        print(f"  python3 watch_wayback.py example.com")
        print(f"  python3 watch_wayback.py https://example.com/")
        sys.exit(1)

    # Extract clean domain
    domain = extract_domain(raw_input)

    if raw_input != domain:
        print(f"{colors.GRAY}Input: {raw_input}{colors.RESET}")
        print(f"{colors.GRAY}Extracted domain: {domain}{colors.RESET}")

    # Find program by scope
    program = find_program_by_scope(domain)

    if program:
        program_name = program.get("program_name", "unknown")
        print(f"{colors.CYAN}[{current_time()}] running Wayback module for '{domain}'{colors.RESET}")
        print(f"{colors.CYAN}📦 Program: {program_name}{colors.RESET}")

        subs = wayback_enum(domain)

        if not subs:
            print(f"{colors.YELLOW}[{current_time()}] No results from Wayback for {domain}{colors.RESET}")
            sys.exit(0)

        valid_subs = filter_subdomains(subs, domain)
        print(f"{colors.GRAY}[{current_time()}] Valid subdomains after filter: {len(valid_subs)}{colors.RESET}")

        scan_data = {
            "timestamp": current_time(),
            "domain": domain,
            "program_name": program_name,
            "source": "wayback",
            "subdomains_count": len(valid_subs),
            "subdomains": valid_subs
        }

        save_wayback_output(program_name, scan_data)

    else:
        print(f"{colors.RED}[{current_time()}] scope '{domain}' does not exist in watchtower{colors.RESET}")
        print(f"{colors.YELLOW}Make sure a program.json with this scope exists in database/<program>/{colors.RESET}")
        sys.exit(1)