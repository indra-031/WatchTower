#!/usr/bin/env python3
"""
WatchTower - Chaos Module
Fetches subdomains from Project Discovery Chaos API.
Saves results to: database/<program-name>/enum-output/chaos.json

Supports:
  - domain.tld
  - https://domain.tld/

Requirements:
  - chaos-client installed (go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest)
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

with (BASE_DIR / "configs" / "api-keys.json").open("r", encoding="utf-8") as _f:
    _API_KEYS = json.load(_f)

CHAOS_API_KEY = _API_KEYS.get("chaos_api_key", "")


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


def run_command_in_bash(command):
    """
    Run a shell command. Returns list of lines or empty list.
    """
    try:
        result = subprocess.run(
            ["bash", "-c", command],
            capture_output=True,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            stderr = result.stderr.strip()
            if stderr:
                print(f"{colors.YELLOW}{stderr[:200]}{colors.RESET}")
            if result.stdout.strip():
                return result.stdout.splitlines()
            return []

        return result.stdout.splitlines()

    except subprocess.TimeoutExpired:
        print(f"{colors.YELLOW}⏰ Timeout{colors.RESET}")
        return []
    except FileNotFoundError:
        print(f"{colors.RED}❌ chaos command not found. Install: go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest{colors.RESET}")
        return []
    except Exception as e:
        print(f"{colors.RED}❌ Error: {e}{colors.RESET}")
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


def chaos_enum(domain: str) -> list:
    """
    Fetch subdomains from Chaos API.
    Returns list of subdomains.
    """
    api_key = CHAOS_API_KEY

    if not api_key:
        print(f"{colors.RED}❌ chaos_api_key not set in configs/api-keys.json{colors.RESET}")
        return []

    # Try chaos-client first
    command = f"chaos -d {domain} -key {api_key} -silent 2>/dev/null"

    print(f"{colors.GRAY}Running: chaos -d {domain}{colors.RESET}")

    results = run_command_in_bash(command)

    if results:
        # chaos returns plain subdomains, one per line
        subs = [line.strip().lower() for line in results if line.strip()]
        print(f"{colors.GRAY}Done for {domain}, results: {len(subs)}{colors.RESET}")
        return subs

    # Fallback: direct API call
    print(f"{colors.GRAY}Chaos CLI failed, trying API...{colors.RESET}")
    command = f'curl -s -H "Authorization: {api_key}" "https://dns.projectdiscovery.io/dns/{domain}/subdomains"'
    results = run_command_in_bash(command)

    if results:
        try:
            full_output = "\n".join(results)
            data = json.loads(full_output)
            subdomains = data.get("subdomains", [])
            if isinstance(subdomains, list):
                subs = [f"{s}.{domain}" for s in subdomains]
                print(f"{colors.GRAY}Done for {domain}, results: {len(subs)}{colors.RESET}")
                return subs
        except json.JSONDecodeError:
            pass

    print(f"{colors.YELLOW}No results for {domain}{colors.RESET}")
    return []


def filter_subdomains(subs: list, domain: str) -> list:
    """
    Filter subdomains that belong to the target domain.
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


def save_chaos_output(program_name: str, data: dict):
    """
    Save scan result to:
    database/<program-name>/enum-output/chaos.json
    """
    safe_name = sanitize_name(program_name)
    output_dir = DATABASE_DIR / safe_name / "enum-output"
    output_file = output_dir / "chaos.json"

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
        print(f"Usage: python3 watch_chaos.py <scope_name | URL>")
        print(f"Examples:")
        print(f"  python3 watch_chaos.py example.com")
        print(f"  python3 watch_chaos.py https://example.com/")
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
        print(f"{colors.CYAN}[{current_time()}] running Chaos module for '{domain}'{colors.RESET}")
        print(f"{colors.CYAN}📦 Program: {program_name}{colors.RESET}")

        subs = chaos_enum(domain)

        if not subs:
            print(f"{colors.YELLOW}[{current_time()}] No results from Chaos for {domain}{colors.RESET}")
            sys.exit(0)

        valid_subs = filter_subdomains(subs, domain)
        print(f"{colors.GRAY}[{current_time()}] Valid subdomains after filter: {len(valid_subs)}{colors.RESET}")

        scan_data = {
            "timestamp": current_time(),
            "domain": domain,
            "program_name": program_name,
            "source": "chaos",
            "subdomains_count": len(valid_subs),
            "subdomains": valid_subs
        }

        save_chaos_output(program_name, scan_data)

    else:
        print(f"{colors.RED}[{current_time()}] scope '{domain}' does not exist in watchtower{colors.RESET}")
        print(f"{colors.YELLOW}Make sure a program.json with this scope exists in database/<program>/{colors.RESET}")
        sys.exit(1)