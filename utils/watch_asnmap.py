#!/usr/bin/env python3
"""
WatchTower - ASN Map

Resolves ASNs to their announced CIDR ranges using ProjectDiscovery's asnmap.

Reads ASNs from:  database/<program>/program.json (asn field)
Writes to:
  database/<program>/asn/asn.json         (scan log, append-only)
  database/<program>/asn/lives-asn.json   (aggregated: ASN -> cidrs)
  database/<program>/asn/asn_done.json    (processed markers)

Usage:
  python3 watch_asnmap.py <domain>
  python3 watch_asnmap.py <domain> --force
  python3 watch_asnmap.py --all
  python3 watch_asnmap.py --all --force

Requirements:
  - asnmap: go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest
"""

import sys
import json
import shutil
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

ASNMAP_TIMEOUT = 120


# =========================
# Helpers
# =========================

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize(name):
    return (name.strip().lower()
            .replace(" ", "-").replace("/", "-")
            .replace("\\", "-").replace(":", "-"))


def normalize_asn(asn):
    """Accept 'AS15169', '15169', 'as15169' → 'AS15169'."""
    s = str(asn).strip().upper()
    if not s.startswith("AS"):
        s = "AS" + s
    return s


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


def asn_output_dir(program_name):
    return DATABASE_DIR / sanitize(program_name) / "asn"


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


# =========================
# asnmap execution
# =========================

def run_asnmap(asn):
    """
    Run asnmap for a single ASN. Returns list of CIDRs, or None if
    asnmap is not installed. Empty list on any other failure.
    """
    cmd = ["asnmap", "-a", asn, "-silent"]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=ASNMAP_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        print(f"     {colors.YELLOW}⏰ asnmap timeout for {asn}{colors.RESET}")
        return []
    except FileNotFoundError:
        return None
    except Exception as e:
        print(f"     {colors.RED}❌ asnmap error: {e}{colors.RESET}")
        return []

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        if stderr:
            print(f"     {colors.YELLOW}{stderr[:200]}{colors.RESET}")
        return []

    cidrs = set()
    for line in (result.stdout or "").splitlines():
        line = line.strip()
        if line and "/" in line:
            cidrs.add(line)
    return sorted(cidrs)


# =========================
# Persistence
# =========================

def save_result(program_name, asn, cidrs):
    d = asn_output_dir(program_name)
    ts = now()

    # 1. scan log
    log_path = d / "asn.json"
    log = load_json_file(log_path)
    if not isinstance(log, dict) or "scans" not in log:
        log = {"scans": []}
    log["scans"].append({
        "timestamp": ts,
        "asn": asn,
        "cidrs_count": len(cidrs),
        "cidrs": cidrs,
    })
    save_json_file(log_path, log)

    # 2. aggregated lives-asn.json
    lives_path = d / "lives-asn.json"
    lives = load_json_file(lives_path)
    if not isinstance(lives, dict):
        lives = {}

    prev_cidrs = set(lives.get(asn, {}).get("cidrs", []))
    new_cidrs = set(cidrs)
    merged = prev_cidrs | new_cidrs
    is_new = asn not in lives

    lives[asn] = {
        "asn": asn,
        "cidrs": sorted(merged),
        "cidrs_count": len(merged),
        "first_seen": lives.get(asn, {}).get("first_seen", ts),
        "last_seen": ts,
    }
    save_json_file(lives_path, lives)

    # 3. done marker
    done_path = d / "asn_done.json"
    done = load_json_file(done_path)
    done[asn] = {"processed_at": ts, "cidrs_count": len(cidrs)}
    save_json_file(done_path, done)

    if is_new:
        print(f"     {colors.GREEN}💾 {asn}: {len(cidrs)} CIDR(s) (new){colors.RESET}")
    else:
        added = len(new_cidrs - prev_cidrs)
        if added:
            print(f"     {colors.GREEN}💾 {asn}: +{added} new ({len(merged)} total){colors.RESET}")
        else:
            print(f"     {colors.GRAY}💾 {asn}: no change ({len(merged)} total){colors.RESET}")


# =========================
# Program processing
# =========================

def process_program(program_name, asns, force=False):
    d = asn_output_dir(program_name)
    done = load_json_file(d / "asn_done.json")

    tested = 0
    skipped = 0
    total_cidrs = 0

    for raw_asn in asns:
        asn = normalize_asn(raw_asn)

        if not force and asn in done:
            print(f"     {colors.GRAY}⏭  {asn} (already processed){colors.RESET}")
            skipped += 1
            continue

        print(f"     {colors.CYAN}🔍 {asn}{colors.RESET}")
        cidrs = run_asnmap(asn)

        if cidrs is None:
            print(f"{colors.RED}❌ asnmap not installed. Install:\n"
                  f"   go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest{colors.RESET}")
            sys.exit(1)

        if not cidrs:
            print(f"     {colors.YELLOW}⚠️  no CIDRs returned for {asn}{colors.RESET}")
            save_result(program_name, asn, [])
        else:
            print(f"     {colors.GREEN}✅ {asn}: {len(cidrs)} CIDR(s){colors.RESET}")
            for c in cidrs[:3]:
                print(f"        {colors.GRAY}{c}{colors.RESET}")
            if len(cidrs) > 3:
                print(f"        {colors.GRAY}... and {len(cidrs) - 3} more{colors.RESET}")
            save_result(program_name, asn, cidrs)
            total_cidrs += len(cidrs)

        tested += 1

    return tested, skipped, total_cidrs


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
                "asns": data.get("asn", []),
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
    positional = [a for a in args if not a.startswith("--")]

    if not shutil.which("asnmap"):
        print(f"{colors.RED}❌ asnmap CLI not found.{colors.RESET}")
        print(f"   Install: go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest{colors.RESET}")
        sys.exit(1)

    print(f"{colors.CYAN}[{now()}] WatchTower — ASN Map{colors.RESET}\n")

    if not all_mode and not positional:
        print("Usage:")
        print("  python3 watch_asnmap.py <domain> [--force]")
        print("  python3 watch_asnmap.py --all [--force]")
        sys.exit(1)

    # Single program
    if not all_mode:
        domain = positional[0].strip().lower().lstrip("*.")
        program = find_program_by_scope(domain)
        if not program:
            print(f"{colors.RED}❌ Scope '{domain}' not found{colors.RESET}")
            sys.exit(1)

        program_name = program.get("program_name", "unknown")
        asns = program.get("asn", [])

        if not asns:
            print(f"{colors.YELLOW}⚠️ No ASNs defined for {program_name}{colors.RESET}")
            sys.exit(0)

        print(f"{colors.CYAN}📦 Program: {program_name}{colors.RESET}")
        print(f"{colors.CYAN}🔢 ASNs   : {len(asns)}{colors.RESET}\n")

        tested, skipped, total_cidrs = process_program(program_name, asns, force=force)

        print()
        print(f"{colors.GREEN}{'='*50}{colors.RESET}")
        print(f"{colors.GREEN}✅ ASN map complete{colors.RESET}")
        print(f"{colors.GREEN}   ASNs processed : {tested}{colors.RESET}")
        if skipped:
            print(f"{colors.CYAN}   Skipped        : {skipped}{colors.RESET}")
        print(f"{colors.GREEN}   Total CIDRs    : {total_cidrs}{colors.RESET}")
        print(f"{colors.GREEN}{'='*50}{colors.RESET}")
        sys.exit(0)

    # All programs
    programs = get_all_programs()
    if not programs:
        print(f"{colors.RED}❌ No programs found{colors.RESET}")
        sys.exit(1)

    total_tested = 0
    total_skipped = 0
    total_cidrs = 0
    programs_with_asns = 0

    for prog in programs:
        pn = prog["name"]
        asns = prog["asns"]

        print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
        if not asns:
            print(f"   {colors.GRAY}no ASNs defined, skipping{colors.RESET}\n")
            continue

        programs_with_asns += 1
        print(f"   ASNs: {len(asns)}\n")

        tested, skipped, cidrs = process_program(pn, asns, force=force)
        total_tested += tested
        total_skipped += skipped
        total_cidrs += cidrs
        print()

    print(f"{colors.GREEN}{'='*50}{colors.RESET}")
    print(f"{colors.GREEN}✅ ASN map complete{colors.RESET}")
    print(f"{colors.GREEN}   Programs (with ASNs) : {programs_with_asns}/{len(programs)}{colors.RESET}")
    print(f"{colors.GREEN}   ASNs processed       : {total_tested}{colors.RESET}")
    if total_skipped:
        print(f"{colors.CYAN}   Skipped              : {total_skipped}{colors.RESET}")
    print(f"{colors.GREEN}   Total CIDRs          : {total_cidrs}{colors.RESET}")
    print(f"{colors.GREEN}{'='*50}{colors.RESET}")