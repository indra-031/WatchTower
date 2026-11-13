#!/usr/bin/env python3
"""
WatchTower - Filter Private IPs
Removes hosts that only resolve to private/non-routable IPs from
dns/lives.json, moving them to dns/lives-private.json for inspection.

Reads:  database/<program>/dns/lives.json
        database/<program>/dns/lives-private.json  (existing, merged)
Writes: database/<program>/dns/lives.json            (public-capable hosts only)
        database/<program>/dns/lives-private.json    (private-only hosts)

A host is kept in lives.json if it has at least one public IP.
Private IPs on that host are stripped from "ips" and stored in "private_ips".

Usage:
  python3 watch_privates_ip_filter.py <domain>
"""

import sys
import json
import re
import ipaddress
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
# Private IP patterns
# =========================

# RFC1918 private IPv4 (10/8, 172.16/12, 192.168/16)
PRIVATE_IPV4_PATTERN = re.compile(
    r"""
    \b
    (?:
        10\.(?:[0-9]{1,3}\.){2}[0-9]{1,3}                            |
        172\.(?:1[6-9]|2[0-9]|3[01])\.(?:[0-9]{1,3}\.){1}[0-9]{1,3}  |
        192\.168\.(?:[0-9]{1,3}\.){1}[0-9]{1,3}
    )\b
    """,
    re.VERBOSE,
)


# =========================
# Helpers
# =========================

def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize_name(name):
    return (name.strip().lower()
            .replace(" ", "-").replace("/", "-")
            .replace("\\", "-").replace(":", "-"))


def load_json(path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")


def find_program_by_scope(scope_name):
    if not DATABASE_DIR.exists():
        return None
    for d in DATABASE_DIR.iterdir():
        if not d.is_dir() or not (d / "program.json").exists():
            continue
        try:
            data = json.loads((d / "program.json").read_text())
        except Exception:
            continue

        # Prefer new key; fall back to legacy "ooscope".
        scopes = (
            data.get("scope", [])
            + data.get("out_of_scope", data.get("ooscope", []))
        )

        for s in scopes:
            clean = s.lstrip("*.").lower()
            if scope_name == clean or scope_name.endswith("." + clean):
                return data
    return None


def is_private_ip(ip):
    """
    RFC1918 private detection: user regex + ipaddress validation.
    """
    if not ip or not isinstance(ip, str):
        return False
    if not PRIVATE_IPV4_PATTERN.search(ip):
        return False
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_non_routable_ip(ip):
    """
    Other non-routable IPs we never want to HTTP-probe:
    loopback, link-local, reserved, multicast, unspecified.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (
        addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def classify_ips(ips):
    """
    Split a list of IP strings into:
      public  -> routable, should be HTTP-probed
      private -> RFC1918 or non-routable
      unknown -> not a valid IP (kept out of both lists, logged separately)
    """
    public, private, unknown = [], [], []
    for raw in ips or []:
        ip = (raw or "").strip()
        if not ip:
            continue
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            unknown.append(ip)
            continue
        if is_private_ip(ip) or is_non_routable_ip(ip):
            private.append(ip)
        else:
            public.append(ip)
    return public, private, unknown


def host_matches_domain(host, domain):
    if not domain:
        return True
    return host == domain or host.endswith("." + domain)


# =========================
# Core
# =========================

def process_program(program_name, domain=None, dry_run=False):
    """
    Filter private IPs for one program.
    Returns a stats dict.
    """
    safe = sanitize_name(program_name)
    lives_file = DATABASE_DIR / safe / "dns" / "lives.json"
    private_file = DATABASE_DIR / safe / "dns" / "lives-private.json"

    if not lives_file.exists():
        print(f"{colors.YELLOW}⚠️ No lives.json for '{program_name}'{colors.RESET}")
        return {"kept": 0, "filtered": 0, "moved_to_private": 0, "moved_to_public": 0, "stripped": 0}

    lives = load_json(lives_file)
    private = load_json(private_file)

    if not lives and not private:
        print(f"{colors.YELLOW}⚠️ lives.json is empty for '{program_name}'{colors.RESET}")
        return {"kept": 0, "filtered": 0, "moved_to_private": 0, "moved_to_public": 0, "stripped": 0}

    moved_to_private = 0
    moved_to_public = 0
    stripped = 0

    # Walk over the union of hosts from both files
    all_hosts = set(lives.keys()) | set(private.keys())

    for host in sorted(all_hosts):
        if not host_matches_domain(host, domain):
            continue

        info = lives.get(host) or private.get(host) or {}
        ips = info.get("ips", []) or []
        public_ips, private_ips, unknown_ips = classify_ips(ips)

        if public_ips:
            # Keep in lives, strip private IPs from primary list
            new_info = dict(info)
            new_info["ips"] = public_ips
            if private_ips:
                new_info["private_ips"] = private_ips
                stripped += 1
            if host in private:
                del private[host]
                moved_to_public += 1
            lives[host] = new_info

        elif private_ips:
            # Only private/non-routable -> move to private
            if host in lives:
                del lives[host]
                moved_to_private += 1
            private[host] = info

        else:
            # No IPs at all (or only unknown) -> keep where it is
            # If it's in private with no IPs, promote to lives (informational)
            if host in private and not unknown_ips:
                private.pop(host, None)
                lives[host] = info

    if not dry_run:
        save_json(lives_file, lives)
        if private:
            save_json(private_file, private)
        elif private_file.exists():
            private_file.unlink()

    return {
        "kept": len(lives),
        "filtered": len(private),
        "moved_to_private": moved_to_private,
        "moved_to_public": moved_to_public,
        "stripped": stripped,
    }


# =========================
# Main
# =========================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 watch_privates_ip_filter.py <domain>")
        print("Example: python3 watch_privates_ip_filter.py example.com")
        print("")
        print("Note: use watch_privates_ip_filter_all.py to run on all programs.")
        sys.exit(1)

    domain = sys.argv[1].strip().lower().lstrip("*.")

    program = find_program_by_scope(domain)
    if not program:
        print(f"{colors.RED}[{current_time()}] scope '{domain}' does not exist{colors.RESET}")
        sys.exit(1)

    program_name = program.get("program_name", "unknown")
    print(f"{colors.CYAN}[{current_time()}] Filtering private IPs for '{domain}'{colors.RESET}")
    print(f"{colors.CYAN}📦 Program: {program_name}{colors.RESET}")

    result = process_program(program_name, domain=domain)

    print()
    print(f"     {colors.GREEN}📋 kept in lives.json   : {result['kept']}{colors.RESET}")
    print(f"     {colors.YELLOW}🔒 moved to lives-private: {result['filtered']}{colors.RESET}")
    if result["moved_to_private"]:
        print(f"     {colors.GRAY}   (moved public→private this run: {result['moved_to_private']}){colors.RESET}")
    if result["moved_to_public"]:
        print(f"     {colors.GRAY}   (moved private→public this run: {result['moved_to_public']}){colors.RESET}")
    if result["stripped"]:
        print(f"     {colors.GRAY}   (hosts with mixed IPs, private stripped: {result['stripped']}){colors.RESET}")

    safe = sanitize_name(program_name)
    print()
    print(f"{colors.GREEN}{'='*50}{colors.RESET}")
    print(f"{colors.GREEN}✅ Filter complete for '{domain}'{colors.RESET}")
    print(f"{colors.GREEN}   lives.json        : {DATABASE_DIR / safe / 'dns' / 'lives.json'}{colors.RESET}")
    if result["filtered"]:
        print(f"{colors.GREEN}   lives-private.json: {DATABASE_DIR / safe / 'dns' / 'lives-private.json'}{colors.RESET}")
    print(f"{colors.GREEN}{'='*50}{colors.RESET}")