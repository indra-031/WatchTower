#!/usr/bin/env python3
"""
WatchTower - Enum All Modules
Runs all enumeration modules on all scopes of all programs.
After enumeration, merges all subdomains into all-subdomains.json
with source tracking.

Scope enforcement:
  - Both new ("out_of_scope") and legacy ("ooscope") keys are honored.
  - OOS wins over scope: any host matching an OOS pattern is dropped,
    even if it also matches a scope pattern.
  - Existing all-subdomains.json is filtered on every run, so OOS
    entries added after the fact are purged automatically.

Modules:
  - Subfinder (CLI)
  - CRT.sh (API)
  - Chaos (CLI)
  - Wayback Machine (API)
  - GAU (CLI)
  - CRTmon (CLI)
  - crt.name (API)
  - AgniOps (API)
  - Assetfinder (CLI)
  - waymore (CLI)
  - Findomain (CLI)
  - github-subdomains (CLI)
  - AbuseIPDB (API, reverse IP lookup)
"""

import sys
import subprocess
import json
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading


# =========================
# Paths
# =========================

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_DIR = BASE_DIR / "database"
ENUM_DIR = BASE_DIR / "enumeration"


# =========================
# Imports from configs/
# =========================

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from configs.colors import colors
from configs.scope import get_scope_lists, is_in_scope


# =========================
# Configuration
# =========================

MODULES = [
    {"name": "Subfinder", "script": "watch_subfinder.py", "enabled": True, "timeout": 600},
    {"name": "CRT.sh", "script": "watch_crtsh.py", "enabled": True, "timeout": 120},
    {"name": "Chaos", "script": "watch_chaos.py", "enabled": True, "timeout": 120},
    {"name": "Wayback", "script": "watch_wayback.py", "enabled": True, "timeout": 600},
    {"name": "GAU", "script": "watch_gau.py", "enabled": True, "timeout": 600},
    {"name": "CRTmon", "script": "watch_crtmon.py", "enabled": True, "timeout": 45},
    {"name": "crt.name", "script": "watch_crtname.py", "enabled": True, "timeout": 120},
    {"name": "AgniOps", "script": "watch_agniops.py", "enabled": True, "timeout": 120},
    {"name": "Assetfinder", "script": "watch_assetfinder.py", "enabled": True, "timeout": 300},
    {"name": "waymore", "script": "watch_waymore.py", "enabled": True, "timeout": 900},
    {"name": "Findomain", "script": "watch_findomain.py", "enabled": True, "timeout": 300},
    {"name": "github-subdomains", "script": "watch_github_subdomains.py", "enabled": True, "timeout": 600},
    {"name": "AbuseIPDB", "script": "watch_abuseipdb.py", "enabled": True, "timeout": 120},
]

SOURCES = {
    "subfinder.json": "subfinder",
    "crtsh.json": "crtsh",
    "chaos.json": "chaos",
    "wayback.json": "wayback",
    "gau.json": "gau",
    "crtmon.json": "crtmon",
    "crtname.json": "crtname",
    "agniops.json": "agniops",
    "assetfinder.json": "assetfinder",
    "waymore.json": "waymore",
    "findomain.json": "findomain",
    "github-subdomains.json": "github-subdomains",
    "abuseipdb.json": "abuseipdb",
}

PARALLEL = True
MAX_WORKERS = 3


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


def run_module_script(script_name: str, scope: str, timeout: int = 600) -> bool:
    script_path = ENUM_DIR / script_name

    if not script_path.exists():
        print(f"     {colors.RED}❌ Script not found: {script_path}{colors.RESET}")
        return False

    print(f"     {colors.WHITE}🔧 {script_name} on {scope}...{colors.RESET}")

    try:
        result = subprocess.run(
            ["python3", str(script_path), scope],
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(ENUM_DIR),
        )

        if result.returncode != 0:
            for line in result.stderr.strip().splitlines()[-3:]:
                print(f"     {colors.RED}{line}{colors.RESET}")
            return False

        stdout_lines = result.stdout.strip().splitlines()
        if stdout_lines:
            summary = stdout_lines[-1]
            if len(summary) > 120:
                summary = summary[:120] + "..."
            print(f"     {colors.GRAY}{summary}{colors.RESET}")

        return True

    except subprocess.TimeoutExpired:
        print(f"     {colors.YELLOW}⏰ Timeout after {timeout}s{colors.RESET}")
        return False
    except Exception as e:
        print(f"     {colors.RED}❌ Error: {e}{colors.RESET}")
        return False


def get_all_programs() -> list:
    if not DATABASE_DIR.exists():
        print(f"{colors.RED}❌ database/ directory not found{colors.RESET}")
        return []

    programs = []
    for program_dir in sorted(DATABASE_DIR.iterdir()):
        if not program_dir.is_dir():
            continue

        program_file = program_dir / "program.json"
        if not program_file.exists():
            continue

        try:
            with program_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, Exception) as e:
            print(f"{colors.YELLOW}⚠️ Skipping {program_file}: {e}{colors.RESET}")
            continue

        scopes = [s.strip() for s in data.get("scope", []) if s and s.strip()]
        if scopes:
            programs.append({
                "program_name": data.get("program_name", program_dir.name),
                "scopes": scopes,
            })

    return programs


def merge_all_subdomains(program_name: str):
    """
    Collect subdomains from all enum output files and build
    all-subdomains.json with source tracking.

    Scope enforcement:
      - Loads scope + out_of_scope from program.json.
      - Filters existing data (removes stale OOS entries).
      - Filters fresh data (drops new OOS entries before merge).
      - OOS takes priority over scope.

    Reads:  database/<program>/enum-output/*.json
    Writes: database/<program>/enum-output/all-subdomains.json
    """
    safe_name = sanitize_name(program_name)
    enum_dir = DATABASE_DIR / safe_name / "enum-output"
    all_subs_file = enum_dir / "all-subdomains.json"

    # Load existing data
    existing = {}
    if all_subs_file.exists():
        try:
            with all_subs_file.open("r", encoding="utf-8") as f:
                raw = json.load(f)
            if isinstance(raw, dict):
                existing = raw
                print(f"     {colors.GRAY}Loaded {len(existing)} existing subdomains{colors.RESET}")
            elif isinstance(raw, list):
                print(f"     {colors.YELLOW}🔄 Old format detected, rebuilding...{colors.RESET}")
                existing = {}
        except (json.JSONDecodeError, Exception):
            existing = {}

    # Load scope + out_of_scope from program.json
    program_file = DATABASE_DIR / safe_name / "program.json"
    program_data = {}
    if program_file.exists():
        try:
            program_data = json.loads(program_file.read_text(encoding="utf-8"))
        except Exception:
            program_data = {}
    scope, oos = get_scope_lists(program_data)

    # Filter existing data — removes any OOS entries written in earlier runs
    oos_removed_existing = 0
    if scope or oos:
        before = len(existing)
        existing = {k: v for k, v in existing.items() if is_in_scope(k, scope, oos)}
        oos_removed_existing = before - len(existing)
        if oos_removed_existing:
            print(f"     {colors.YELLOW}⏭  {oos_removed_existing} stale OOS subdomain(s) removed{colors.RESET}")

    # Scan all source files into `fresh`
    fresh = {}
    new_count = 0

    for file_name, source_label in SOURCES.items():
        source_file = enum_dir / file_name
        if not source_file.exists():
            continue

        try:
            with source_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, Exception):
            continue

        for scan in data.get("scans", []):
            domain = scan.get("domain") or scan.get("target", "unknown")
            timestamp = scan.get("timestamp", "unknown")

            subs = scan.get("subdomains", [])
            if not subs:
                subs = scan.get("reverse_lookup_hostnames", [])

            for sub in subs:
                if sub not in fresh:
                    fresh[sub] = {
                        "first_seen": timestamp,
                        "last_seen": timestamp,
                        "sources": {},
                    }

                if timestamp < fresh[sub]["first_seen"]:
                    fresh[sub]["first_seen"] = timestamp
                if timestamp > fresh[sub]["last_seen"]:
                    fresh[sub]["last_seen"] = timestamp

                if source_label not in fresh[sub]["sources"]:
                    fresh[sub]["sources"][source_label] = {
                        "first_seen": timestamp,
                        "last_seen": timestamp,
                        "domain": domain,
                    }
                else:
                    src = fresh[sub]["sources"][source_label]
                    if timestamp < src["first_seen"]:
                        src["first_seen"] = timestamp
                    if timestamp > src["last_seen"]:
                        src["last_seen"] = timestamp

    # Filter fresh by scope — drops any new OOS subdomains before merge
    oos_removed_fresh = 0
    if scope or oos:
        before = len(fresh)
        fresh = {k: v for k, v in fresh.items() if is_in_scope(k, scope, oos)}
        oos_removed_fresh = before - len(fresh)
        if oos_removed_fresh:
            print(f"     {colors.YELLOW}⏭  {oos_removed_fresh} new OOS subdomain(s) filtered{colors.RESET}")

    # If nothing new and existing wasn't cleaned, short-circuit
    if not fresh and oos_removed_existing == 0:
        print(f"     {colors.YELLOW}⚠️ No subdomains found{colors.RESET}")
        return len(existing)

    # Merge fresh into existing
    for sub, info in fresh.items():
        if sub not in existing:
            new_count += 1
            existing[sub] = info
        else:
            if info["first_seen"] < existing[sub].get("first_seen", info["first_seen"]):
                existing[sub]["first_seen"] = info["first_seen"]
            if info["last_seen"] > existing[sub].get("last_seen", info["last_seen"]):
                existing[sub]["last_seen"] = info["last_seen"]
            for src, src_info in info["sources"].items():
                if src not in existing[sub].get("sources", {}):
                    existing[sub].setdefault("sources", {})[src] = src_info
                else:
                    old_src = existing[sub]["sources"][src]
                    if src_info["first_seen"] < old_src.get("first_seen", src_info["first_seen"]):
                        old_src["first_seen"] = src_info["first_seen"]
                    if src_info["last_seen"] > old_src.get("last_seen", src_info["last_seen"]):
                        old_src["last_seen"] = src_info["last_seen"]

    # Sort
    existing = dict(sorted(existing.items()))

    # Save
    enum_dir.mkdir(parents=True, exist_ok=True)
    with all_subs_file.open("w", encoding="utf-8") as f:
        json.dump(existing, f, indent=4, ensure_ascii=False)

    # Stats
    total = len(existing)
    source_counts = {}
    for sub, info in existing.items():
        for src in info.get("sources", {}):
            source_counts[src] = source_counts.get(src, 0) + 1

    if new_count:
        print(f"     {colors.GREEN}🆕 {new_count} new subdomains{colors.RESET}")
    print(f"     {colors.CYAN}📋 Total unique: {total}{colors.RESET}")
    for src, count in sorted(source_counts.items()):
        print(f"        {colors.GRAY}{src}: {count}{colors.RESET}")
    print(f"     {colors.GREEN}💾 Saved → {all_subs_file}{colors.RESET}")

    return total


def run_scope_modules(scope: str, program_name: str, modules: list) -> dict:
    results = {}
    for module in modules:
        if not module.get("enabled", True):
            continue
        success = run_module_script(module["script"], scope, module.get("timeout", 600))
        results[module["name"]] = success
        if success:
            print(f"     {colors.GREEN}✅ {module['name']} done for {scope}{colors.RESET}")
        else:
            print(f"     {colors.YELLOW}⚠️ {module['name']} failed on {scope}{colors.RESET}")
    return results


# =========================
# Main
# =========================

if __name__ == "__main__":
    print(f"{colors.CYAN}[{current_time()}] WatchTower — Enum All{colors.RESET}")
    print()

    if not ENUM_DIR.exists():
        print(f"{colors.RED}❌ enumeration/ directory not found: {ENUM_DIR}{colors.RESET}")
        sys.exit(1)

    programs = get_all_programs()
    if not programs:
        print(f"{colors.RED}❌ No programs found. Run watch_sync_programs.py first.{colors.RESET}")
        sys.exit(1)

    enabled_modules = [m for m in MODULES if m.get("enabled", True)]

    print(f"{colors.CYAN}📦 Programs : {len(programs)}{colors.RESET}")
    print(f"{colors.CYAN}🔧 Modules  : {', '.join(m['name'] for m in enabled_modules)}{colors.RESET}")
    print(f"{colors.CYAN}⚡ Mode     : {'Parallel' if PARALLEL else 'Sequential'}{colors.RESET}")
    if PARALLEL:
        print(f"{colors.CYAN}   Workers : {MAX_WORKERS}{colors.RESET}")
    print()

    total_modules_run = 0
    total_success = 0
    total_failed = 0
    lock = threading.Lock()

    for program in programs:
        program_name = program["program_name"]
        scopes = program["scopes"]

        print(f"{colors.BLUE}{'='*60}{colors.RESET}")
        print(f"{colors.BLUE}🎯 {program_name} — {len(scopes)} scope(s){colors.RESET}")
        print(f"{colors.BLUE}{'='*60}{colors.RESET}")

        if PARALLEL and len(scopes) > 1:
            with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(scopes))) as executor:
                futures = {
                    executor.submit(run_scope_modules, scope, program_name, enabled_modules): scope
                    for scope in scopes
                }
                for future in as_completed(futures):
                    scope = futures[future]
                    try:
                        results = future.result()
                        with lock:
                            for success in results.values():
                                total_modules_run += 1
                                if success:
                                    total_success += 1
                                else:
                                    total_failed += 1
                    except Exception as e:
                        print(f"{colors.RED}❌ Thread error on {scope}: {e}{colors.RESET}")
                        with lock:
                            total_modules_run += len(enabled_modules)
                            total_failed += len(enabled_modules)
        else:
            for i, scope in enumerate(scopes, 1):
                print(f"\n{colors.CYAN}[{i}/{len(scopes)}] {scope}{colors.RESET}")
                results = run_scope_modules(scope, program_name, enabled_modules)
                for success in results.values():
                    total_modules_run += 1
                    if success:
                        total_success += 1
                    else:
                        total_failed += 1

        print(f"\n{colors.MAGENTA}🔄 Merging subdomains...{colors.RESET}")
        merge_all_subdomains(program_name)
        print()

    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ Complete{colors.RESET}")
    print(f"{colors.GREEN}   Programs : {len(programs)}{colors.RESET}")
    print(f"{colors.GREEN}   Run      : {total_modules_run}{colors.RESET}")
    print(f"{colors.GREEN}   Success  : {total_success}{colors.RESET}")
    if total_failed:
        print(f"{colors.YELLOW}   Failed   : {total_failed}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")