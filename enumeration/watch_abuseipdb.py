#!/usr/bin/env python3
"""
WatchTower - AbuseIPDB Module
Reverse IP lookup / IP reputation via AbuseIPDB API v2.
Saves results to: database/<program-name>/enum-output/abuseipdb.json

Supports:
  - IP address:  1.2.3.4
  - Domain:      example.com  (resolves to IPs, then checks each)

The "hostnames" field returned by AbuseIPDB is effectively the reverse DNS result.
"""

import sys
import re
import json
import socket
import ipaddress
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

with (BASE_DIR / "configs" / "api-keys.json").open("r", encoding="utf-8") as _f:
    _API_KEYS = json.load(_f)

ABUSEIPDB_API_KEY = _API_KEYS.get("abuseipdb_api_key", "")


# =========================
# Helpers
# =========================

def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


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


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def resolve_domain(domain: str) -> list:
    """
    Resolve domain to list of IPv4 addresses.
    """
    try:
        _, _, ips = socket.gethostbyname_ex(domain)
        return ips
    except (socket.gaierror, Exception):
        return []


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


def find_program_by_ip(ip: str) -> dict | None:
    """
    Search all program.json files in database/ for matching IP
    (direct ip field or inside any cidr range).
    """
    if not DATABASE_DIR.exists():
        return None

    try:
        target_ip = ipaddress.ip_address(ip)
    except ValueError:
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

        if ip in data.get("ip", []):
            return data

        for cidr in data.get("cidr", []):
            try:
                if target_ip in ipaddress.ip_network(cidr, strict=False):
                    return data
            except ValueError:
                continue

    return None


def abuseipdb_check(ip: str) -> dict | None:
    """
    Query AbuseIPDB API v2 /check for a single IP.
    Returns the 'data' field of the response, or None on error.
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json",
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": "90",
        "verbose": "",
    }

    print(f"{colors.GRAY}Checking: {ip}{colors.RESET}")

    try:
        response = requests.get(url, headers=headers, params=params, timeout=30)

        if response.status_code == 401:
            print(f"{colors.RED}❌ Unauthorized - check abuseipdb_api_key in configs/api-keys.json{colors.RESET}")
            return None

        if response.status_code == 429:
            print(f"{colors.YELLOW}⚠️ Rate limit hit for {ip}{colors.RESET}")
            return None

        if response.status_code != 200:
            print(f"{colors.YELLOW}Error: {response.status_code} - {response.reason}{colors.RESET}")
            return None

        payload = response.json()
        return payload.get("data", {})

    except requests.Timeout:
        print(f"{colors.YELLOW}⏰ Timeout for {ip}{colors.RESET}")
        return None
    except requests.ConnectionError:
        print(f"{colors.RED}❌ Connection error for {ip}{colors.RESET}")
        return None
    except Exception as e:
        print(f"{colors.RED}❌ Error: {e}{colors.RESET}")
        return None


def save_abuseipdb_output(program_name: str, data: dict):
    """
    Save scan result to:
    database/<program-name>/enum-output/abuseipdb.json
    """
    safe_name = sanitize_name(program_name)
    output_dir = DATABASE_DIR / safe_name / "enum-output"
    output_file = output_dir / "abuseipdb.json"

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
        print(f"Usage: python3 watch_abuseipdb.py <IP | domain>")
        print(f"Examples:")
        print(f"  python3 watch_abuseipdb.py 1.2.3.4")
        print(f"  python3 watch_abuseipdb.py example.com")
        sys.exit(1)

    target = raw_input.strip()

    # Determine target IPs
    if is_valid_ip(target):
        target_ips = [target]
        print(f"{colors.GRAY}Target IP: {target}{colors.RESET}")
        program = find_program_by_ip(target)
    else:
        print(f"{colors.GRAY}Resolving domain: {target}{colors.RESET}")
        target_ips = resolve_domain(target)
        if not target_ips:
            print(f"{colors.RED}❌ Could not resolve {target}{colors.RESET}")
            sys.exit(1)
        print(f"{colors.GRAY}Resolved IPs: {', '.join(target_ips)}{colors.RESET}")
        program = find_program_by_scope(target) or find_program_by_ip(target_ips[0])

    if not program:
        print(f"{colors.RED}[{current_time()}] target '{target}' does not exist in watchtower{colors.RESET}")
        print(f"{colors.YELLOW}Make sure a program.json with this scope/cidr/ip exists in database/<program>/{colors.RESET}")
        sys.exit(1)

    program_name = program.get("program_name", "unknown")
    print(f"{colors.CYAN}[{current_time()}] running AbuseIPDB module for '{target}'{colors.RESET}")
    print(f"{colors.CYAN}📦 Program: {program_name}{colors.RESET}")

    if not ABUSEIPDB_API_KEY or len(ABUSEIPDB_API_KEY) < 32:
        print(f"{colors.RED}❌ abuseipdb_api_key not set properly in configs/api-keys.json{colors.RESET}")
        sys.exit(1)

    # Check each IP
    results = []
    for ip in target_ips:
        data = abuseipdb_check(ip)
        if data:
            results.append({
                "ip": ip,
                "hostnames": data.get("hostnames", []),
                "domain": data.get("domain", ""),
                "country_code": data.get("countryCode", ""),
                "country_name": data.get("countryName", ""),
                "isp": data.get("isp", ""),
                "usage_type": data.get("usageType", ""),
                "is_public": data.get("isPublic", False),
                "is_tor": data.get("isTor", False),
                "is_whitelisted": data.get("isWhitelisted", False),
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "num_distinct_users": data.get("numDistinctUsers", 0),
                "last_reported_at": data.get("lastReportedAt"),
            })

    if not results:
        print(f"{colors.YELLOW}[{current_time()}] No results from AbuseIPDB for {target}{colors.RESET}")
        sys.exit(0)

    all_hostnames = set()
    for r in results:
        all_hostnames.update(r["hostnames"])

    scan_data = {
        "timestamp": current_time(),
        "target": target,
        "program_name": program_name,
        "source": "abuseipdb",
        "ips_checked": len(results),
        "reverse_lookup_hostnames": sorted(all_hostnames),
        "results": results,
    }

    save_abuseipdb_output(program_name, scan_data)
    print(f"{colors.GRAY}Total unique hostnames found: {len(all_hostnames)}{colors.RESET}")