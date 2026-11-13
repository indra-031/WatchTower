#!/usr/bin/env python3
"""
WatchTower - waymore Module
Discovers URLs via waymore and extracts unique hostnames (subdomains).
Saves results to: database/<program-name>/enum-output/waymore.json

Requirements:
  - waymore installed:
    pipx install waymore
    (or: pip install waymore)
"""

import sys
import re
import json
import subprocess
import tempfile
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


def run_command(command: str, timeout: int = 900) -> bool:
    """
    Run a shell command. Returns True on success, False otherwise.
    """
    try:
        result = subprocess.run(
            ["bash", "-c", command],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        if result.returncode != 0:
            stderr = result.stderr.strip()
            if stderr:
                print(f"{colors.YELLOW}{stderr[:300]}{colors.RESET}")
            return False

        return True

    except subprocess.TimeoutExpired:
        print(f"{colors.YELLOW}⏰ Timeout after {timeout}s{colors.RESET}")
        return False
    except FileNotFoundError:
        print(f"{colors.RED}❌ waymore not found. Install: pipx install waymore{colors.RESET}")
        return False
    except Exception as e:
        print(f"{colors.RED}❌ Error: {e}{colors.RESET}")
        return False


def waymore_enum(domain: str) -> list:
    """
    Run waymore in URL-only mode, then extract unique hostnames.
    """
    tmp_file = Path(tempfile.gettempdir()) / f"waymore_{domain.replace('.', '_')}.txt"

    if tmp_file.exists():
        tmp_file.unlink()

    command = (
        f"waymore -i {domain} -mode U -oU {tmp_file} "
        f"-n -p 1 2>/dev/null"
    )

    print(f"{colors.GRAY}Running: waymore -i {domain} -mode U{colors.RESET}")

    ok = run_command(command)

    if not ok or not tmp_file.exists():
        print(f"{colors.YELLOW}No output file produced for {domain}{colors.RESET}")
        return []

    try:
        urls = tmp_file.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception as e:
        print(f"{colors.RED}❌ Could not read waymore output: {e}{colors.RESET}")
        return []
    finally:
        try:
            tmp_file.unlink()
        except Exception:
            pass

    hostnames = set()

    for url in urls:
        url = url.strip()
        if not url:
            continue
        try:
            parsed = urlparse(url)
            host = parsed.hostname
            if host:
                hostnames.add(host.lower())
        except Exception:
            continue

    subs = sorted(hostnames)
    print(f"{colors.GRAY}Done for {domain}, unique hostnames: {len(subs)}{colors.RESET}")
    return subs


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

    return sorted(set(filtered))


def save_output(program_name: str, data: dict):
    safe_name = sanitize_name(program_name)
    output_dir = DATABASE_DIR / safe_name / "enum-output"
    output_file = output_dir / "waymore.json"

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
        print(f"Usage: python3 watch_waymore.py <domain>")
        print(f"Example: python3 watch_waymore.py example.com")
        print(f"")
        print(f"Requirements:")
        print(f"  waymore: pipx install waymore")
        sys.exit(1)

    domain = raw_input.strip().lower().lstrip("*.")

    program = find_program_by_scope(domain)

    if not program:
        print(f"{colors.RED}[{current_time()}] scope '{domain}' does not exist in watchtower{colors.RESET}")
        print(f"{colors.YELLOW}Make sure a program.json with this scope exists in database/<program>/{colors.RESET}")
        sys.exit(1)

    program_name = program.get("program_name", "unknown")
    print(f"{colors.CYAN}[{current_time()}] running waymore module for '{domain}'{colors.RESET}")
    print(f"{colors.CYAN}📦 Program: {program_name}{colors.RESET}")

    subs = waymore_enum(domain)

    if not subs:
        print(f"{colors.YELLOW}[{current_time()}] No results from waymore for {domain}{colors.RESET}")
        sys.exit(0)

    valid_subs = filter_subdomains(subs, domain)
    print(f"{colors.GRAY}[{current_time()}] Valid subdomains after filter: {len(valid_subs)}{colors.RESET}")

    scan_data = {
        "timestamp": current_time(),
        "domain": domain,
        "program_name": program_name,
        "source": "waymore",
        "subdomains_count": len(valid_subs),
        "subdomains": valid_subs,
    }

    save_output(program_name, scan_data)