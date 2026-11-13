#!/usr/bin/env python3
"""
WatchTower - CRT Monitor (crtmon CLI wrapper)
Runs crtmon for quick real-time subdomain discovery.
Saves to: database/<program>/enum-output/crtmon.json

Note: crtmon is a real-time tool. This wrapper runs it for 45 seconds.
For historical data, use watch_crtsh.py instead.
"""

import sys
import subprocess
import re
import json
import tempfile
import shutil
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
    return name.strip().lower().replace(" ", "-").replace("/", "-").replace("\\", "-").replace(":", "-")


def run_command_in_bash(command, timeout=60):
    try:
        result = subprocess.run(
            ["bash", "-c", command],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        if result.stdout.strip():
            return result.stdout.strip()
        return ""
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""


def find_program_by_scope(scope_name: str) -> dict | None:
    if not DATABASE_DIR.exists():
        return None
    for program_dir in DATABASE_DIR.iterdir():
        if not program_dir.is_dir():
            continue
        program_file = program_dir / "program.json"
        if not program_file.exists():
            continue
        try:
            with program_file.open("r") as f:
                data = json.load(f)
        except:
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
            if scope_name == clean_scope or scope_name.endswith("." + clean_scope):
                return data
    return None


def crtmon_quick_scan(domain: str) -> list:
    """
    Run crtmon for 30 seconds inside an isolated temp directory,
    capture stdout, parse subdomains. The temp directory is removed
    afterwards so crtmon cannot leave artifacts in the caller's cwd.
    """
    tmpdir = tempfile.mkdtemp(prefix="watchtower_crtmon_")
    try:
        # cd into the temp dir before running crtmon so any files
        # it writes end up there instead of enumeration/.
        command = f"cd {tmpdir} && timeout 30 crtmon -target {domain} 2>&1"

        print(f"{colors.GRAY}Running crtmon for 30s on {domain}...{colors.RESET}")

        output = run_command_in_bash(command, timeout=45)

        if not output:
            return []

        subdomains = set()
        log_pattern = re.compile(r'^\d{2}:\d{2}:\d{2}\s+(WARN|INFO|DEBU|ERRO)')

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            # Skip log lines
            if log_pattern.match(line):
                continue
            # Skip lines with URLs or paths
            if '://' in line or line.startswith('http'):
                continue
            # Skip Go error lines
            if line.startswith('E') and '.go:' in line:
                continue

            # Check if it's a domain
            if '.' in line and domain in line:
                clean = line.lower().strip()
                # Remove leading numbers like "1. ", "2. " etc.
                clean = re.sub(r'^\d+\.\s*', '', clean)
                subdomains.add(clean)

        return sorted(list(subdomains))

    finally:
        # Always clean up, even on timeout or exception
        shutil.rmtree(tmpdir, ignore_errors=True)


def filter_subdomains(subs: list, domain: str) -> list:
    pattern = r'\.?\s*' + re.escape(domain) + r'$'
    filtered = []
    for sub in subs:
        sub = sub.strip().lower()
        if not sub or '*' in sub:
            continue
        if re.search(pattern, sub, re.IGNORECASE):
            filtered.append(sub)
    return sorted(list(set(filtered)))


def save_crtmon_output(program_name: str, data: dict):
    safe_name = sanitize_name(program_name)
    output_dir = DATABASE_DIR / safe_name / "enum-output"
    output_file = output_dir / "crtmon.json"
    output_dir.mkdir(parents=True, exist_ok=True)

    existing = {"scans": []}
    if output_file.exists():
        try:
            with output_file.open("r") as f:
                existing = json.load(f)
        except:
            pass

    existing["scans"].append(data)

    with output_file.open("w") as f:
        json.dump(existing, f, indent=4, ensure_ascii=False)

    print(f"{colors.GREEN}💾 Scan saved to {output_file}{colors.RESET}")


# =========================
# Main
# =========================

if __name__ == "__main__":
    raw_input = sys.argv[1] if len(sys.argv) > 1 else False

    if raw_input is False:
        print(f"Usage: python3 watch_crtmon.py <scope_name | URL>")
        print(f"Examples:")
        print(f"  python3 watch_crtmon.py example.com")
        print(f"  python3 watch_crtmon.py https://example.com/")
        print(f"")
        print(f"Note: This runs crtmon for 30 seconds of real-time monitoring.")
        print(f"      For historical data, use watch_crtsh.py instead.")
        sys.exit(1)

    domain = extract_domain(raw_input)
    if raw_input != domain:
        print(f"{colors.GRAY}Input: {raw_input}{colors.RESET}")
        print(f"{colors.GRAY}Extracted domain: {domain}{colors.RESET}")

    program = find_program_by_scope(domain)

    if program:
        program_name = program.get("program_name", "unknown")
        print(f"{colors.CYAN}[{current_time()}] running CRTmon module for '{domain}'{colors.RESET}")
        print(f"{colors.CYAN}📦 Program: {program_name}{colors.RESET}")

        subs = crtmon_quick_scan(domain)

        if not subs:
            print(f"{colors.YELLOW}[{current_time()}] No new subdomains found in 30s window{colors.RESET}")
            sys.exit(0)

        valid_subs = filter_subdomains(subs, domain)
        print(f"{colors.GRAY}[{current_time()}] Valid subdomains: {len(valid_subs)}{colors.RESET}")

        scan_data = {
            "timestamp": current_time(),
            "domain": domain,
            "program_name": program_name,
            "source": "crtmon",
            "subdomains_count": len(valid_subs),
            "subdomains": valid_subs
        }

        save_crtmon_output(program_name, scan_data)

    else:
        print(f"{colors.RED}[{current_time()}] scope '{domain}' does not exist in watchtower{colors.RESET}")
        sys.exit(1)