#!/usr/bin/env python3
"""
WatchTower - DNS All Modules
Runs DNS resolution (shuffledns + dnsx) on all subdomains of all programs.
Reads from: database/<program>/enum-output/all-subdomains.json
Saves to:   database/<program>/dns/dns.json
            database/<program>/dns/lives.json
            database/<program>/changes/changes.json    (dead/revived events)

lives.json tracks liveness across runs:
  - status: "alive" | "dead"
  - first_seen / last_seen / last_changed / died_at
  - changes: per-host change history (status transitions)

Scope enforcement:
  - out_of_scope (and legacy "ooscope") is applied to both existing
    and fresh data. OOS wins over scope. Stale OOS entries are purged
    from lives.json on every run.
"""

import sys
import subprocess
import tempfile
import json
import threading
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


# =========================
# Paths
# =========================

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_DIR = BASE_DIR / "database"
DNS_MODULE_DIR = BASE_DIR / "dns"


# =========================
# Imports from configs/
# =========================

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from configs.colors import colors
from configs.changes import append_to_program_log
from configs.scope import load_scope_from_path, is_in_scope


# =========================
# Configuration
# =========================

PARALLEL = True
MAX_WORKERS = 3
DNS_TIMEOUT = 600


# =========================
# Helpers
# =========================

def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize_name(name: str) -> str:
    return (name.strip().lower()
            .replace(" ", "-").replace("/", "-")
            .replace("\\", "-").replace(":", "-"))


def run_command_in_bash(command, timeout=600):
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
                for line in stderr.splitlines()[-3:]:
                    print(f"     {colors.YELLOW}{line}{colors.RESET}")
            if result.stdout.strip():
                return result.stdout.splitlines()
            return False
        return result.stdout.splitlines()
    except subprocess.TimeoutExpired:
        print(f"     {colors.YELLOW}⏰ Timeout{colors.RESET}")
        return False
    except Exception as e:
        print(f"     {colors.RED}❌ {e}{colors.RESET}")
        return False


def get_all_programs() -> list:
    if not DATABASE_DIR.exists():
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
                prog_data = json.load(f)
        except (json.JSONDecodeError, Exception):
            continue

        program_name = prog_data.get("program_name", program_dir.name)
        scopes = prog_data.get("scope", [])
        scopes = [s.strip() for s in scopes if s and s.strip()]

        all_subs_file = program_dir / "enum-output" / "all-subdomains.json"
        if not all_subs_file.exists():
            print(f"{colors.YELLOW}⚠️ No all-subdomains.json for {program_name}{colors.RESET}")
            continue

        try:
            with all_subs_file.open("r", encoding="utf-8") as f:
                all_subs = json.load(f)
        except (json.JSONDecodeError, Exception):
            continue

        if isinstance(all_subs, dict):
            subdomains = sorted(all_subs.keys())
        elif isinstance(all_subs, list):
            subdomains = sorted(all_subs)
        else:
            subdomains = []

        if not subdomains:
            print(f"{colors.YELLOW}⚠️ No subdomains for {program_name}{colors.RESET}")
            continue

        programs.append({
            "program_name": program_name,
            "scopes": scopes,
            "subdomains": subdomains,
            "path": program_dir,
        })

    return programs


def get_resolvers_file() -> str:
    local = DNS_MODULE_DIR / "brute-files" / "resolvers.txt"
    if local.exists():
        return str(local)
    home = Path.home() / ".resolvers.txt"
    if home.exists():
        return str(home)
    return "8.8.8.8,1.1.1.1"


def run_dns(domain: str, subdomains: list) -> list:
    if not subdomains:
        return []

    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as f:
        for sub in subdomains:
            f.write(f"{sub}\n")
        subdomains_file = f.name

    resolvers = get_resolvers_file()

    command = (
        f"shuffledns -l {subdomains_file} "
        f"-r {resolvers} "
        f"-mode resolve "
        f"-sw {domain} "
        f"| dnsx -silent -t 10 -rl 30 -resp -json"
    )

    print(f"     {colors.GRAY}Running dnsx on {domain}...{colors.RESET}")
    results = run_command_in_bash(command, DNS_TIMEOUT)

    try:
        Path(subdomains_file).unlink()
    except Exception:
        pass

    if not results:
        return []

    parsed = []
    for line in results:
        line = line.strip()
        if not line:
            continue
        try:
            parsed.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return parsed


def save_dns_output(program_path: Path, domain: str, results: list,
                    scope=None, oos=None):
    """Save DNS scan log to dns.json (OOS hosts filtered)."""
    scope = scope or []
    oos = oos or []
    dns_dir = program_path / "dns"
    dns_dir.mkdir(parents=True, exist_ok=True)
    output_file = dns_dir / "dns.json"

    existing = {"scans": []}
    if output_file.exists():
        try:
            existing = json.loads(output_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    scan_entry = {
        "timestamp": current_time(),
        "domain": domain,
        "source": "shuffledns+dnsx",
        "lives_count": 0,
        "hosts": [],
    }

    for obj in results:
        host = obj.get("host", "")
        if host and (scope or oos) and not is_in_scope(host, scope, oos):
            continue
        scan_entry["hosts"].append({
            "host": host,
            "ips": obj.get("a", []),
            "cname": obj.get("cname", ""),
            "status_code": obj.get("status_code", ""),
        })

    scan_entry["lives_count"] = len(scan_entry["hosts"])
    existing["scans"].append(scan_entry)

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(existing, f, indent=4, ensure_ascii=False)

    print(f"     {colors.GREEN}💾 dns.json saved{colors.RESET}")


def save_lives(program_path: Path, domain: str, results: list,
               scope=None, oos=None):
    """
    Update lives.json with dead/alive tracking (per domain).

    Scope enforcement:
      - existing entries matching OOS are purged before merge
      - fresh results matching OOS are skipped
    All transitions append to database/<program>/changes/changes.json.
    """
    scope = scope or []
    oos = oos or []
    dns_dir = program_path / "dns"
    dns_dir.mkdir(parents=True, exist_ok=True)
    lives_file = dns_dir / "lives.json"

    existing = {}
    if lives_file.exists():
        try:
            existing = json.loads(lives_file.read_text(encoding="utf-8"))
        except Exception:
            existing = {}

    # Purge stale OOS entries from lives.json
    if scope or oos:
        before = len(existing)
        existing = {k: v for k, v in existing.items() if is_in_scope(k, scope, oos)}
        removed = before - len(existing)
        if removed:
            print(f"     {colors.YELLOW}⏭  {removed} host(s) removed (out of scope){colors.RESET}")

    program_name = program_path.name
    ts = current_time()
    resolved_hosts = set()
    new_count = 0
    revived_count = 0

    # 1. Update / add alive hosts
    for obj in results:
        host = obj.get("host", "")
        if not host:
            continue
        if (scope or oos) and not is_in_scope(host, scope, oos):
            print(f"     {colors.GRAY}⏭  {host} (out of scope){colors.RESET}")
            continue
        resolved_hosts.add(host)

        old = existing.get(host, {})
        old_changes = old.get("changes") if isinstance(old.get("changes"), list) else []
        was_dead = old.get("status") == "dead"

        current = {
            "domain": domain,
            "ips": obj.get("a", []),
            "cname": obj.get("cname", ""),
            "last_seen": ts,
            "status": "alive",
            "first_seen": old.get("first_seen") or ts,
            "changes": old_changes,
            "last_changed": old.get("last_changed") or ts,
        }

        if not old:
            new_count += 1

        if was_dead:
            revived_count += 1
            change = {
                "id": f"chg_revived_{host}",
                "timestamp": ts,
                "type": "subdomain_revived",
                "severity": "high",
                "field": "status",
                "old": "dead",
                "new": "alive",
                "context": {"ips": current["ips"]},
            }
            current["changes"].append(change)
            current["last_changed"] = ts
            append_to_program_log(program_name, host, "dns", [change])
            print(f"     {colors.GREEN}🔔 {host}: revived{colors.RESET}")

        existing[host] = current

    # 2. Mark previously-alive hosts as dead (this domain only)
    dead_count = 0
    for host, info in existing.items():
        if info.get("domain") != domain:
            continue
        if host in resolved_hosts:
            continue
        if info.get("status") == "dead":
            continue

        change = {
            "id": f"chg_dead_{host}",
            "timestamp": ts,
            "type": "subdomain_dead",
            "severity": "high",
            "field": "status",
            "old": "alive",
            "new": "dead",
            "context": {},
        }

        info["status"] = "dead"
        info["died_at"] = ts
        info["last_changed"] = ts
        if not isinstance(info.get("changes"), list):
            info["changes"] = []
        info["changes"].append(change)

        dead_count += 1
        append_to_program_log(program_name, host, "dns", [change])
        print(f"     {colors.RED}🔔 {host}: marked dead{colors.RESET}")

    with lives_file.open("w", encoding="utf-8") as f:
        json.dump(existing, f, indent=4, ensure_ascii=False)

    if new_count:
        print(f"     {colors.GREEN}🆕 {new_count} new live hosts{colors.RESET}")
    if revived_count:
        print(f"     {colors.GREEN}♻️  {revived_count} revived{colors.RESET}")
    if dead_count:
        print(f"     {colors.RED}💀 {dead_count} marked dead{colors.RESET}")
    alive_total = sum(1 for i in existing.values() if i.get("status") == "alive")
    print(f"     {colors.CYAN}📋 Total live: {alive_total} "
          f"(dead: {len(existing) - alive_total}){colors.RESET}")


def process_domain(program: dict, domain: str) -> int:
    program_path = program["path"]
    subdomains = program["subdomains"]
    scope = program.get("scope_list", [])
    oos = program.get("oos_list", [])

    print(f"     {colors.WHITE}🔧 DNS on {domain} ({len(subdomains)} subs)...{colors.RESET}")

    results = run_dns(domain, subdomains)

    if not results:
        print(f"     {colors.YELLOW}⚠️ No live hosts for {domain}{colors.RESET}")
        save_dns_output(program_path, domain, [], scope=scope, oos=oos)
        save_lives(program_path, domain, [], scope=scope, oos=oos)
        return 0

    print(f"     {colors.GREEN}✅ {len(results)} live hosts{colors.RESET}")
    save_dns_output(program_path, domain, results, scope=scope, oos=oos)
    save_lives(program_path, domain, results, scope=scope, oos=oos)

    return len(results)


# =========================
# Main
# =========================

if __name__ == "__main__":
    print(f"{colors.CYAN}[{current_time()}] WatchTower — DNS All{colors.RESET}")
    print()

    programs = get_all_programs()

    if not programs:
        print(f"{colors.RED}❌ No programs with subdomains found.{colors.RESET}")
        print(f"{colors.YELLOW}   Run watch_enum_all.py first.{colors.RESET}")
        sys.exit(1)

    # Attach scope lists to each program entry
    for prog in programs:
        scope_list, oos_list = load_scope_from_path(prog["path"] / "program.json")
        prog["scope_list"] = scope_list
        prog["oos_list"] = oos_list

    print(f"{colors.CYAN}📦 Programs : {len(programs)}{colors.RESET}")
    print(f"{colors.CYAN}⚡ Mode     : {'Parallel' if PARALLEL else 'Sequential'}{colors.RESET}")
    if PARALLEL:
        print(f"{colors.CYAN}   Workers : {MAX_WORKERS}{colors.RESET}")
    print()

    total_live = 0
    total_domains = 0
    lock = threading.Lock()

    for program in programs:
        program_name = program["program_name"]
        scopes = program["scopes"]
        subdomains = program["subdomains"]
        scope_list = program["scope_list"]
        oos_list = program["oos_list"]

        print(f"{colors.BLUE}{'='*60}{colors.RESET}")
        print(f"{colors.BLUE}🎯 {program_name}{colors.RESET}")
        print(f"{colors.BLUE}   Scopes: {', '.join(scopes)}{colors.RESET}")
        print(f"{colors.BLUE}   Subs  : {len(subdomains)}{colors.RESET}")
        if oos_list:
            print(f"{colors.BLUE}   OOS   : {', '.join(oos_list)}{colors.RESET}")
        print(f"{colors.BLUE}{'='*60}{colors.RESET}")

        if PARALLEL and len(scopes) > 1:
            with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, len(scopes))) as executor:
                futures = {
                    executor.submit(process_domain, program, scope): scope
                    for scope in scopes
                }
                for future in as_completed(futures):
                    scope = futures[future]
                    try:
                        live_count = future.result()
                        with lock:
                            total_domains += 1
                            total_live += live_count
                    except Exception as e:
                        print(f"{colors.RED}❌ Thread error on {scope}: {e}{colors.RESET}")
                        with lock:
                            total_domains += 1
        else:
            for i, scope in enumerate(scopes, 1):
                print(f"\n{colors.CYAN}[{i}/{len(scopes)}] Domain: {scope}{colors.RESET}")
                live_count = process_domain(program, scope)
                total_domains += 1
                total_live += live_count

        print()

    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ DNS All completed{colors.RESET}")
    print(f"{colors.GREEN}   Programs : {len(programs)}{colors.RESET}")
    print(f"{colors.GREEN}   Domains  : {total_domains}{colors.RESET}")
    print(f"{colors.GREEN}   Live     : {total_live}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")