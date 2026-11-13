#!/usr/bin/env python3
"""
WatchTower - Wildcard DNS Test
Checks if a domain has wildcard DNS configured by attempting to resolve
random non-existent subdomains. If they resolve, wildcard filtering is
required during brute force.

Already-tested domains are recorded in dns/wildcard_done.json and
skipped on subsequent runs unless --force is used.

Saves results to: database/<program-name>/dns/wildcard-test.json

Usage:
  python3 watch_wildcard_dns_test.py <domain>
  python3 watch_wildcard_dns_test.py <domain> --force
"""

import sys
import socket
import json
from datetime import datetime
from pathlib import Path


# =========================
# Project root discovery
# =========================

def _find_project_root(start: Path) -> Path:
    current = start.resolve()
    for _ in range(10):
        if (current / "configs" / "colors.py").exists() and (current / "database").exists():
            return current
        if (current / "app.py").exists():
            return current
        if current.parent == current:
            break
        current = current.parent
    return start.resolve().parent.parent


BASE_DIR = _find_project_root(Path(__file__))
DATABASE_DIR = BASE_DIR / "database"


# =========================
# Imports from configs/
# =========================

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from configs.colors import colors


# =========================
# Configuration
# =========================

WILDCARD_PROBE_STRING = (
    "k9m2xr7vq4ztw8nb3jc6fh1p5dys0leguaiovkjhgfdsapoiuytrewqmnbvcxzlkjhg"
    "fdaspoiuytrewqmnbvcxzlkjhgfdsapoiuytrewqmnbvcxzlkjhgfdsa1234567890abcd"
)

ATTEMPTS = 3


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


def find_program_by_scope(scope_name: str):
    if not DATABASE_DIR.exists():
        print(f"{colors.RED}❌ database/ directory not found{colors.RESET}")
        return None

    for program_dir in DATABASE_DIR.iterdir():
        if not program_dir.is_dir() or program_dir.name.startswith("_"):
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


# =========================
# Done tracking
# =========================

def get_done_file(program_name):
    safe = sanitize_name(program_name)
    return DATABASE_DIR / safe / "dns" / "wildcard_done.json"


def load_done(program_name):
    f = get_done_file(program_name)
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_done(program_name, done):
    f = get_done_file(program_name)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(done, indent=4, ensure_ascii=False), encoding="utf-8")


def mark_done(program_name, domain, wildcard_detected):
    done = load_done(program_name)
    done[domain] = {
        "tested_at": current_time(),
        "wildcard_detected": bool(wildcard_detected),
    }
    save_done(program_name, done)


# =========================
# Core
# =========================

def build_probe_subdomain(domain: str, attempt_index: int = 0) -> str:
    if attempt_index == 0:
        return f"{WILDCARD_PROBE_STRING}.{domain}"
    return f"{WILDCARD_PROBE_STRING}-{attempt_index}.{domain}"


def try_resolve(hostname: str):
    try:
        results = socket.getaddrinfo(hostname, None)
        ips = set()
        for r in results:
            ips.add(r[4][0])
        return True, sorted(ips)
    except socket.gaierror:
        return False, []
    except Exception:
        return False, []


def wildcard_test(domain: str) -> dict:
    attempts = []
    wildcard_detected = False
    wildcard_ips = set()

    for i in range(ATTEMPTS):
        subdomain = build_probe_subdomain(domain, i)
        print(f"{colors.GRAY}  [{i+1}/{ATTEMPTS}] Probing: {subdomain}{colors.RESET}")

        resolved, ips = try_resolve(subdomain)

        attempts.append({
            "subdomain": subdomain,
            "resolved": resolved,
            "ips": ips,
        })

        if resolved:
            wildcard_detected = True
            wildcard_ips.update(ips)
            print(f"{colors.YELLOW}  ⚠️  Resolved → {', '.join(ips)}{colors.RESET}")
        else:
            print(f"{colors.GRAY}  ✓ NXDOMAIN{colors.RESET}")

    return {
        "probe_string": WILDCARD_PROBE_STRING,
        "wildcard_detected": wildcard_detected,
        "wildcard_ips": sorted(wildcard_ips),
        "attempts": attempts,
    }


def save_output(program_name: str, data: dict):
    safe_name = sanitize_name(program_name)
    output_dir = DATABASE_DIR / safe_name / "dns"
    output_file = output_dir / "wildcard-test.json"

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
    args = sys.argv[1:]
    force = "--force" in args
    non_flags = [a for a in args if not a.startswith("--")]

    if not non_flags:
        print("Usage: python3 watch_wildcard_dns_test.py <domain> [--force]")
        print("Example: python3 watch_wildcard_dns_test.py example.com")
        print("")
        print("Options:")
        print("  --force   re-test even if the domain is in wildcard_done.json")
        sys.exit(1)

    domain = non_flags[0].strip().lower().lstrip("*.")

    program = find_program_by_scope(domain)
    if not program:
        print(f"{colors.RED}[{current_time()}] scope '{domain}' does not exist in watchtower{colors.RESET}")
        print(f"{colors.YELLOW}Make sure a program.json with this scope exists in database/<program>/{colors.RESET}")
        sys.exit(1)

    program_name = program.get("program_name", "unknown")

    # Done check
    done = load_done(program_name)
    if not force and domain in done:
        info = done[domain]
        print(f"{colors.GREEN}[{current_time()}] ✅ Already tested '{domain}' "
              f"at {info.get('tested_at', '?')} "
              f"(wildcard={info.get('wildcard_detected')}){colors.RESET}")
        print(f"{colors.GRAY}   Use --force to re-test.{colors.RESET}")
        sys.exit(0)

    print(f"{colors.CYAN}[{current_time()}] running Wildcard test for '{domain}'{colors.RESET}")
    print(f"{colors.CYAN}📦 Program: {program_name}{colors.RESET}")

    result = wildcard_test(domain)

    if result["wildcard_detected"]:
        print(f"{colors.YELLOW}[{current_time()}] ⚠️  WILDCARD DETECTED on {domain}{colors.RESET}")
        print(f"{colors.YELLOW}   IPs: {', '.join(result['wildcard_ips'])}{colors.RESET}")
        print(f"{colors.YELLOW}   Brute force must use wildcard filtering.{colors.RESET}")
    else:
        print(f"{colors.GREEN}[{current_time()}] ✅ No wildcard on {domain} (safe for brute force){colors.RESET}")

    scan_data = {
        "timestamp": current_time(),
        "domain": domain,
        "program_name": program_name,
        "source": "wildcard-test",
        **result,
    }

    save_output(program_name, scan_data)
    mark_done(program_name, domain, result["wildcard_detected"])