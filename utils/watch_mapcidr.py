#!/usr/bin/env python3
"""
WatchTower - CIDR Map

Expands CIDR ranges into individual IPs using ProjectDiscovery's mapcidr.

Reads CIDRs from:
  database/<program>/program.json           (cidr field)
  database/<program>/asn/lives-asn.json     (ASN-derived, optional)

Writes to:
  database/<program>/cidr/cidr.json          (scan log, append-only)
  database/<program>/cidr/lives-cidr.json    (aggregated: CIDR -> ips)
  database/<program>/cidr/cidr_done.json     (processed markers)

Usage:
  python3 watch_mapcidr.py <domain>
  python3 watch_mapcidr.py <domain> --force
  python3 watch_mapcidr.py <domain> --no-asn
  python3 watch_mapcidr.py <domain> --limit 4096
  python3 watch_mapcidr.py --all
  python3 watch_mapcidr.py --all --limit 0    (no cap — be careful!)

Safety:
  CIDRs larger than MAX_IPS_DEFAULT (4096 = /20) are skipped unless
  --limit is raised. --limit 0 disables the cap entirely.

Requirements:
  - mapcidr: go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest
"""

import sys
import json
import shutil
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

MAPCIDR_TIMEOUT = 300
MAX_IPS_DEFAULT = 4096  # /20


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


def cidr_output_dir(program_name):
    return DATABASE_DIR / sanitize(program_name) / "cidr"


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


def count_ips(cidr):
    """Return the number of addresses in the CIDR, or 0 if invalid."""
    try:
        net = ipaddress.ip_network(cidr, strict=False)
        return net.num_addresses
    except ValueError:
        return 0


# =========================
# mapcidr execution
# =========================

def run_mapcidr(cidr, max_ips):
    """
    Expand a CIDR into IPs.
    Returns (ips_list, error_or_None).
    Errors: "too-large", "invalid", "mapcidr-missing", "timeout", "failed".
    """
    n = count_ips(cidr)
    if n == 0:
        return [], "invalid"
    if max_ips > 0 and n > max_ips:
        return [], "too-large"

    cmd = ["mapcidr", "-cidr", cidr, "-silent"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=MAPCIDR_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return [], "timeout"
    except FileNotFoundError:
        return [], "mapcidr-missing"
    except Exception:
        return [], "failed"

    if result.returncode != 0:
        return [], "failed"

    ips = set()
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ipaddress.ip_address(line)
            ips.add(line)
        except ValueError:
            continue
    return sorted(ips), None


# =========================
# CIDR source discovery
# =========================

def collect_cidrs(program_name, include_asn=True):
    """
    Return list of (cidr, source) tuples.
    Sources: "program" (from program.json:cidr), "asn" (from asn/lives-asn.json).
    """
    safe = sanitize(program_name)
    prog_dir = DATABASE_DIR / safe
    prog_file = prog_dir / "program.json"

    out = []
    seen = set()

    # program.json:cidr
    if prog_file.exists():
        try:
            data = json.loads(prog_file.read_text())
            for cidr in data.get("cidr", []):
                cidr = cidr.strip()
                if not cidr:
                    continue
                key = (cidr, "program")
                if key in seen:
                    continue
                seen.add(key)
                out.append(key)
        except Exception:
            pass

    # asn/lives-asn.json
    if include_asn:
        asn_lives = prog_dir / "asn" / "lives-asn.json"
        if asn_lives.exists():
            try:
                data = json.loads(asn_lives.read_text())
                for asn_info in data.values():
                    for cidr in asn_info.get("cidrs", []):
                        cidr = cidr.strip()
                        if not cidr:
                            continue
                        key = (cidr, "asn")
                        if key in seen:
                            continue
                        seen.add(key)
                        out.append(key)
            except Exception:
                pass

    return out


# =========================
# Persistence
# =========================

def save_result(program_name, cidr, source, ips):
    d = cidr_output_dir(program_name)
    ts = now()

    # 1. scan log
    log_path = d / "cidr.json"
    log = load_json_file(log_path)
    if not isinstance(log, dict) or "scans" not in log:
        log = {"scans": []}
    log["scans"].append({
        "timestamp": ts,
        "cidr": cidr,
        "source": source,
        "ips_count": len(ips),
    })
    save_json_file(log_path, log)

    # 2. aggregated
    lives_path = d / "lives-cidr.json"
    lives = load_json_file(lives_path)
    if not isinstance(lives, dict):
        lives = {}

    is_new = cidr not in lives
    prev_ips = set(lives.get(cidr, {}).get("ips", []))
    new_ips = set(ips)
    merged_ips = prev_ips | new_ips

    prev_sources = set()
    if cidr in lives:
        old = lives[cidr]
        if isinstance(old.get("sources"), list):
            prev_sources = set(old["sources"])
        elif "source" in old:
            prev_sources = {old["source"]}
    prev_sources.add(source)

    lives[cidr] = {
        "cidr": cidr,
        "sources": sorted(prev_sources),
        "ips": sorted(merged_ips),
        "ips_count": len(merged_ips),
        "first_seen": lives.get(cidr, {}).get("first_seen", ts),
        "last_seen": ts,
    }
    save_json_file(lives_path, lives)

    # 3. done
    done_path = d / "cidr_done.json"
    done = load_json_file(done_path)
    done[cidr] = {"processed_at": ts, "ips_count": len(ips), "source": source}
    save_json_file(done_path, done)

    if is_new:
        print(f"     {colors.GREEN}💾 {cidr}: {len(ips)} IP(s) [{source}]{colors.RESET}")
    else:
        added = len(new_ips - prev_ips)
        if added:
            print(f"     {colors.GREEN}💾 {cidr}: +{added} new ({len(merged_ips)} total){colors.RESET}")
        else:
            print(f"     {colors.GRAY}💾 {cidr}: no change ({len(merged_ips)} total){colors.RESET}")


# =========================
# Program processing
# =========================

def process_program(program_name, max_ips, force=False, include_asn=True):
    d = cidr_output_dir(program_name)
    done = load_json_file(d / "cidr_done.json")

    cidrs = collect_cidrs(program_name, include_asn=include_asn)
    if not cidrs:
        return 0, 0, 0, 0

    tested = 0
    skipped = 0
    total_ips = 0
    too_large = 0

    for cidr, source in cidrs:
        if not force and cidr in done:
            print(f"     {colors.GRAY}⏭  {cidr} [{source}] (already processed){colors.RESET}")
            skipped += 1
            continue

        n = count_ips(cidr)
        print(f"     {colors.CYAN}🔍 {cidr} [{source}] ({n} addr){colors.RESET}")

        ips, err = run_mapcidr(cidr, max_ips)

        if err == "mapcidr-missing":
            print(f"{colors.RED}❌ mapcidr not installed. Install:\n"
                  f"   go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest{colors.RESET}")
            sys.exit(1)
        elif err == "too-large":
            print(f"     {colors.YELLOW}⚠️  skipped: {n} IPs > limit {max_ips} "
                  f"(use --limit {n} or higher){colors.RESET}")
            too_large += 1
            continue
        elif err == "invalid":
            print(f"     {colors.YELLOW}⚠️  invalid CIDR: {cidr}{colors.RESET}")
            continue
        elif err == "timeout":
            print(f"     {colors.YELLOW}⏰ timeout expanding {cidr}{colors.RESET}")
            continue
        elif err == "failed":
            print(f"     {colors.RED}❌ mapcidr failed for {cidr}{colors.RESET}")
            continue

        if not ips:
            print(f"     {colors.YELLOW}⚠️  no IPs returned for {cidr}{colors.RESET}")
            save_result(program_name, cidr, source, [])
        else:
            print(f"     {colors.GREEN}✅ {cidr}: {len(ips)} IP(s){colors.RESET}")
            save_result(program_name, cidr, source, ips)
            total_ips += len(ips)

        tested += 1

    return tested, skipped, total_ips, too_large


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
            progs.append({"name": data.get("program_name", d.name)})
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

    limit = MAX_IPS_DEFAULT
    positional = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--limit" and i + 1 < len(args):
            try:
                limit = int(args[i + 1])
            except ValueError:
                pass
            i += 2
        elif a.startswith("--"):
            i += 1
        else:
            positional.append(a)
            i += 1

    if not shutil.which("mapcidr"):
        print(f"{colors.RED}❌ mapcidr CLI not found.{colors.RESET}")
        print(f"   Install: go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest{colors.RESET}")
        sys.exit(1)

    if not all_mode and not positional:
        print("Usage:")
        print("  python3 watch_mapcidr.py <domain> [--force] [--no-asn] [--limit N]")
        print("  python3 watch_mapcidr.py --all [--force] [--no-asn] [--limit N]")
        print("")
        print(f"Default --limit: {MAX_IPS_DEFAULT} IPs per CIDR (use --limit 0 for no cap)")
        sys.exit(1)

    print(f"{colors.CYAN}[{now()}] WatchTower — CIDR Map{colors.RESET}")
    print(f"{colors.GRAY}   Limit: {limit if limit > 0 else 'unlimited'} IP(s) per CIDR{colors.RESET}")
    if no_asn:
        print(f"{colors.GRAY}   ASN-derived CIDRs: disabled{colors.RESET}")
    print()

    # Single program
    if not all_mode:
        domain = positional[0].strip().lower().lstrip("*.")
        program = find_program_by_scope(domain)
        if not program:
            print(f"{colors.RED}❌ Scope '{domain}' not found{colors.RESET}")
            sys.exit(1)

        program_name = program.get("program_name", "unknown")
        cidrs = collect_cidrs(program_name, include_asn=not no_asn)

        if not cidrs:
            print(f"{colors.YELLOW}⚠️ No CIDRs found for {program_name}{colors.RESET}")
            print(f"{colors.GRAY}   checked: program.json:cidr"
                  f"{' + asn/lives-asn.json' if not no_asn else ''}{colors.RESET}")
            sys.exit(0)

        print(f"{colors.CYAN}📦 Program: {program_name}{colors.RESET}")
        print(f"{colors.CYAN}🔢 CIDRs  : {len(cidrs)}{colors.RESET}\n")

        tested, skipped, total_ips, too_large = process_program(
            program_name, limit, force=force, include_asn=not no_asn,
        )

        print()
        print(f"{colors.GREEN}{'='*50}{colors.RESET}")
        print(f"{colors.GREEN}✅ CIDR map complete{colors.RESET}")
        print(f"{colors.GREEN}   CIDRs processed : {tested}{colors.RESET}")
        if skipped:
            print(f"{colors.CYAN}   Skipped         : {skipped}{colors.RESET}")
        if too_large:
            print(f"{colors.YELLOW}   Too large       : {too_large} (raise --limit){colors.RESET}")
        print(f"{colors.GREEN}   Total IPs       : {total_ips}{colors.RESET}")
        print(f"{colors.GREEN}{'='*50}{colors.RESET}")
        sys.exit(0)

    # All programs
    programs = get_all_programs()
    if not programs:
        print(f"{colors.RED}❌ No programs found{colors.RESET}")
        sys.exit(1)

    total_tested = 0
    total_skipped = 0
    total_ips = 0
    total_too_large = 0

    for prog in programs:
        pn = prog["name"]
        print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")

        tested, skipped, ips, too_large = process_program(
            pn, limit, force=force, include_asn=not no_asn,
        )

        if tested == 0 and skipped == 0 and too_large == 0:
            print(f"   {colors.GRAY}no CIDRs, skipping{colors.RESET}\n")
            continue

        total_tested += tested
        total_skipped += skipped
        total_ips += ips
        total_too_large += too_large
        print()

    print(f"{colors.GREEN}{'='*50}{colors.RESET}")
    print(f"{colors.GREEN}✅ CIDR map complete{colors.RESET}")
    print(f"{colors.GREEN}   CIDRs processed : {total_tested}{colors.RESET}")
    if total_skipped:
        print(f"{colors.CYAN}   Skipped         : {total_skipped}{colors.RESET}")
    if total_too_large:
        print(f"{colors.YELLOW}   Too large       : {total_too_large}{colors.RESET}")
    print(f"{colors.GREEN}   Total IPs       : {total_ips}{colors.RESET}")
    print(f"{colors.GREEN}{'='*50}{colors.RESET}")