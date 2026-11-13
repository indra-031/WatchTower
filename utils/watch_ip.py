#!/usr/bin/env python3
"""
WatchTower - IP Enrichment

Processes the "ip" field of program.json (single IP addresses).

For each IP:
  - Validate / normalize (IPv4 and IPv6)
  - Reverse DNS (PTR) lookup
  - ASN enrichment via asnmap -ip (if asnmap is installed)

Writes to:
  database/<program>/ip/ip.json         (scan log, append-only)
  database/<program>/ip/lives-ip.json   (aggregated: ip -> enriched info)
  database/<program>/ip/ip_done.json    (processed markers)

Downstream consumers (portscan, screenshots, vhost, ...) read
lives-ip.json together with cidr/lives-cidr.json.

Usage:
  python3 watch_ip.py <domain>
  python3 watch_ip.py <domain> --force
  python3 watch_ip.py <domain> --no-asn
  python3 watch_ip.py <domain> --no-rdns
  python3 watch_ip.py --all
  python3 watch_ip.py --all --force

Requirements:
  - asnmap (optional, for ASN enrichment):
    go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
"""

import sys
import json
import shutil
import socket
import ipaddress
import subprocess
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

ASNMAP_TIMEOUT = 30
RDNS_TIMEOUT = 5


# =========================
# Helpers
# =========================

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize(name):
    return (name.strip().lower()
            .replace(" ", "-").replace("/", "-")
            .replace("\\", "-").replace(":", "-"))


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
        scopes = (
            data.get("scope", [])
            + data.get("out_of_scope", data.get("ooscope", []))
        )
        for s in scopes:
            clean = s.lstrip("*.").lower()
            if scope_name == clean or scope_name.endswith("." + clean):
                return data
    return None


def ip_output_dir(program_name):
    return DATABASE_DIR / sanitize(program_name) / "ip"


def load_json_file(path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_json_file(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")


def normalize_ip(raw):
    """
    Validate and normalize an IP string.
    Returns a canonical string (compressed IPv6) or None if invalid.
    """
    if not raw or not isinstance(raw, str):
        return None
    s = raw.strip()
    if not s:
        return None
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        return None


# =========================
# Enrichment
# =========================

def reverse_dns(ip, timeout=RDNS_TIMEOUT):
    """
    Return PTR hostname or None. Uses socket.gethostbyaddr with a
    short-timeout wrapper (system call has no native timeout support).
    """
    old_default = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        host, _aliases, _addrs = socket.gethostbyaddr(ip)
        return host.rstrip(".").lower() if host else None
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        return None
    except Exception:
        return None
    finally:
        socket.setdefaulttimeout(old_default)


def asnmap_lookup(ip):
    """
    Query asnmap for a single IP.
    Returns dict with as_number/as_name/as_country/as_range or None.
    Returns False if asnmap is not installed (distinguishes "not present"
    from "no result").
    """
    if not shutil.which("asnmap"):
        return False

    cmd = ["asnmap", "-ip", ip, "-json", "-silent"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=ASNMAP_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        print(f"     {colors.YELLOW}⏰ asnmap timeout for {ip}{colors.RESET}")
        return None
    except Exception as e:
        print(f"     {colors.RED}❌ asnmap error for {ip}: {e}{colors.RESET}")
        return None

    if result.returncode != 0:
        return None

    stdout = (result.stdout or "").strip()
    if not stdout:
        return None

    # Try JSONL first, then single-object JSON
    lines = [l.strip() for l in stdout.splitlines() if l.strip()]
    for line in lines:
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(obj, dict):
            continue
        return {
            "asn": obj.get("as_number") or obj.get("asn"),
            "as_name": obj.get("as_name"),
            "as_country": obj.get("as_country"),
            "as_range": obj.get("as_range") or [],
        }
    return None


def enrich_ip(ip, do_rdns=True, do_asn=True):
    """
    Build enriched info for a single IP.
    """
    try:
        addr = ipaddress.ip_address(ip)
        version = "v4" if addr.version == 4 else "v6"
    except ValueError:
        version = "unknown"

    info = {
        "ip": ip,
        "ip_version": version,
        "reverse_dns": None,
        "asn": None,
        "as_name": None,
        "as_country": None,
        "as_range": [],
    }

    if do_rdns:
        rdns = reverse_dns(ip)
        if rdns:
            info["reverse_dns"] = rdns
            print(f"     {colors.GRAY}↩  rDNS: {rdns}{colors.RESET}")

    if do_asn:
        asn_data = asnmap_lookup(ip)
        if asn_data is False:
            # asnmap not installed — inform once per run, no error
            if not getattr(enrich_ip, "_warned", False):
                print(f"     {colors.YELLOW}⚠️  asnmap not installed, skipping ASN enrichment{colors.RESET}")
                print(f"        install: go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest")
                enrich_ip._warned = True
        elif asn_data:
            info["asn"] = asn_data["asn"]
            info["as_name"] = asn_data["as_name"]
            info["as_country"] = asn_data["as_country"]
            info["as_range"] = asn_data["as_range"] or []
            if asn_data["asn"]:
                print(f"     {colors.GRAY}↩  {asn_data['asn']} "
                      f"{asn_data.get('as_name') or ''}".rstrip() + colors.RESET)

    return info


# =========================
# Persistence
# =========================

def save_result(program_name, ip, info):
    d = ip_output_dir(program_name)
    ts = now()

    # 1. scan log
    log_path = d / "ip.json"
    log = load_json_file(log_path)
    if not isinstance(log, dict) or "scans" not in log:
        log = {"scans": []}
    log["scans"].append({
        "timestamp": ts,
        **info,
    })
    save_json_file(log_path, log)

    # 2. aggregated
    lives_path = d / "lives-ip.json"
    lives = load_json_file(lives_path)
    if not isinstance(lives, dict):
        lives = {}

    is_new = ip not in lives
    entry = dict(info)
    entry["first_seen"] = lives.get(ip, {}).get("first_seen", ts)
    entry["last_seen"] = ts
    lives[ip] = entry
    save_json_file(lives_path, lives)

    # 3. done marker
    done_path = d / "ip_done.json"
    done = load_json_file(done_path)
    done[ip] = {"processed_at": ts}
    save_json_file(done_path, done)

    if is_new:
        print(f"     {colors.GREEN}💾 {ip} (new){colors.RESET}")
    else:
        print(f"     {colors.GRAY}💾 {ip} (refreshed){colors.RESET}")


# =========================
# Program processing
# =========================

def process_program(program_name, ips, force=False, do_rdns=True, do_asn=True):
    d = ip_output_dir(program_name)
    done = load_json_file(d / "ip_done.json")

    tested = 0
    skipped = 0
    invalid = 0

    for raw_ip in ips:
        ip = normalize_ip(raw_ip)
        if not ip:
            print(f"     {colors.YELLOW}⚠️  invalid IP: {raw_ip!r}{colors.RESET}")
            invalid += 1
            continue

        if not force and ip in done:
            print(f"     {colors.GRAY}⏭  {ip} (already processed){colors.RESET}")
            skipped += 1
            continue

        print(f"     {colors.CYAN}🔍 {ip}{colors.RESET}")
        info = enrich_ip(ip, do_rdns=do_rdns, do_asn=do_asn)
        save_result(program_name, ip, info)
        tested += 1

    return tested, skipped, invalid


def get_all_programs():
    if not DATABASE_DIR.exists():
        return []
    progs = []
    for d in DATABASE_DIR.iterdir():
        if not d.is_dir() or d.name.startswith("_"):
            continue
        if not (d / "program.json").exists():
            continue
        try:
            data = json.loads((d / "program.json").read_text())
            progs.append({
                "name": data.get("program_name", d.name),
                "ips": data.get("ip", []),
            })
        except Exception:
            pass
    return progs


# =========================
# Main
# =========================

if __name__ == "__main__":
    args = sys.argv[1:]
    all_mode = "--all" in args
    force = "--force" in args
    no_asn = "--no-asn" in args
    no_rdns = "--no-rdns" in args
    positional = [a for a in args if not a.startswith("--")]

    if not all_mode and not positional:
        print("Usage:")
        print("  python3 watch_ip.py <domain> [--force] [--no-asn] [--no-rdns]")
        print("  python3 watch_ip.py --all [--force] [--no-asn] [--no-rdns]")
        sys.exit(1)

    print(f"{colors.CYAN}[{now()}] WatchTower — IP Enrichment{colors.RESET}")
    if no_asn:
        print(f"{colors.GRAY}   ASN enrichment : disabled{colors.RESET}")
    if no_rdns:
        print(f"{colors.GRAY}   Reverse DNS    : disabled{colors.RESET}")
    print()

    # Single program
    if not all_mode:
        domain = positional[0].strip().lower().lstrip("*.")
        program = find_program_by_scope(domain)
        if not program:
            print(f"{colors.RED}❌ Scope '{domain}' not found{colors.RESET}")
            sys.exit(1)

        program_name = program.get("program_name", "unknown")
        ips = program.get("ip", [])

        if not ips:
            print(f"{colors.YELLOW}⚠️ No IPs defined for {program_name}{colors.RESET}")
            sys.exit(0)

        print(f"{colors.CYAN}📦 Program: {program_name}{colors.RESET}")
        print(f"{colors.CYAN}🔢 IPs    : {len(ips)}{colors.RESET}\n")

        tested, skipped, invalid = process_program(
            program_name, ips, force=force,
            do_rdns=not no_rdns, do_asn=not no_asn,
        )

        print()
        print(f"{colors.GREEN}{'='*50}{colors.RESET}")
        print(f"{colors.GREEN}✅ IP enrichment complete{colors.RESET}")
        print(f"{colors.GREEN}   Processed : {tested}{colors.RESET}")
        if skipped:
            print(f"{colors.CYAN}   Skipped   : {skipped}{colors.RESET}")
        if invalid:
            print(f"{colors.YELLOW}   Invalid   : {invalid}{colors.RESET}")
        print(f"{colors.GREEN}{'='*50}{colors.RESET}")
        sys.exit(0)

    # All programs
    programs = get_all_programs()
    if not programs:
        print(f"{colors.RED}❌ No programs found{colors.RESET}")
        sys.exit(1)

    total_tested = 0
    total_skipped = 0
    total_invalid = 0
    programs_with_ips = 0

    for prog in programs:
        pn = prog["name"]
        ips = prog["ips"]

        print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
        if not ips:
            print(f"   {colors.GRAY}no IPs defined, skipping{colors.RESET}\n")
            continue

        programs_with_ips += 1
        print(f"   IPs: {len(ips)}\n")

        tested, skipped, invalid = process_program(
            pn, ips, force=force,
            do_rdns=not no_rdns, do_asn=not no_asn,
        )
        total_tested += tested
        total_skipped += skipped
        total_invalid += invalid
        print()

    print(f"{colors.GREEN}{'='*50}{colors.RESET}")
    print(f"{colors.GREEN}✅ IP enrichment complete{colors.RESET}")
    print(f"{colors.GREEN}   Programs (with IPs) : {programs_with_ips}/{len(programs)}{colors.RESET}")
    print(f"{colors.GREEN}   Processed           : {total_tested}{colors.RESET}")
    if total_skipped:
        print(f"{colors.CYAN}   Skipped             : {total_skipped}{colors.RESET}")
    if total_invalid:
        print(f"{colors.YELLOW}   Invalid             : {total_invalid}{colors.RESET}")
    print(f"{colors.GREEN}{'='*50}{colors.RESET}")