#!/usr/bin/env python3
"""
WatchTower - DNS Module
Runs dnsx (with shuffledns) on subdomains from subfinder output
and saves live hosts with their IPs to:
database/<program-name>/dns/dns.json
database/<program-name>/dns/lives.json

lives.json tracks liveness across runs:
  - status: "alive" | "dead"
  - first_seen / last_seen / last_changed / died_at
  - changes: per-host change history (status transitions)

Scope enforcement:
  - out_of_scope (and legacy "ooscope") is applied to both existing
    and fresh data. OOS wins over scope.
"""

import sys
import os
import subprocess
import re
import tempfile
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


# =========================
# Paths
# =========================

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_DIR = BASE_DIR / "database"
DNS_DIR = BASE_DIR / "dns"


# =========================
# Imports from configs/
# =========================

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from configs.colors import colors
from configs.changes import append_to_program_log
from configs.scope import load_scope_from_path, is_in_scope


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
    return (name.strip().lower()
            .replace(" ", "-").replace("/", "-")
            .replace("\\", "-").replace(":", "-"))


def run_command_in_bash(command):
    try:
        result = subprocess.run(
            ["bash", "-c", command],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode != 0:
            print(f"{colors.YELLOW}Error occurred:{colors.RESET} {result.stderr[:500]}")
            return False
        return result.stdout.splitlines()
    except subprocess.TimeoutExpired:
        print(f"{colors.YELLOW}⏰ Command timed out{colors.RESET}")
        return False
    except subprocess.CalledProcessError as exc:
        print(f"{colors.RED}Status: FAIL{colors.RESET} {exc.returncode} "
              f"{exc.output[:200] if exc.output else ''}")
        return False


def get_subdomains(program_name: str, domain: str) -> list:
    safe_name = sanitize_name(program_name)
    subfinder_file = DATABASE_DIR / safe_name / "enum-output" / "subfinder.json"

    if not subfinder_file.exists():
        print(f"{colors.YELLOW}⚠️ No subfinder.json for '{program_name}'{colors.RESET}")
        print(f"{colors.YELLOW}   Run watch_subfinder.py first{colors.RESET}")
        return []

    try:
        with subfinder_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, Exception) as e:
        print(f"{colors.RED}❌ Error reading subfinder.json: {e}{colors.RESET}")
        return []

    all_subdomains = set()
    for scan in data.get("scans", []):
        if scan.get("domain") == domain:
            all_subdomains.update(scan.get("subdomains", []))

    if not all_subdomains:
        print(f"{colors.YELLOW}⚠️ No subdomains for '{domain}' in '{program_name}'{colors.RESET}")
        return []

    subdomains_list = sorted(all_subdomains)
    print(f"{colors.CYAN}📋 Loaded {len(subdomains_list)} unique subdomains for {domain}{colors.RESET}")
    return subdomains_list


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
            with program_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, Exception):
            continue

        scopes = (
            data.get("scope", [])
            + data.get("out_of_scope", data.get("ooscope", []))
        )

        for scope in scopes:
            clean_scope = scope.lstrip("*.").lower()
            if scope_name == clean_scope or scope_name.endswith("." + clean_scope):
                return data

    return None


def run_dnsx(subdomains_list: list, domain: str) -> list:
    if not subdomains_list:
        print(f"{colors.YELLOW}⚠️ No subdomains to resolve{colors.RESET}")
        return []

    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as temp_file:
        for sub in subdomains_list:
            temp_file.write(f"{sub}\n")
        subdomains_file = temp_file.name

    resolvers_file = DNS_DIR / "brute-files" / "resolvers.txt"
    if resolvers_file.exists():
        resolver_path = str(resolvers_file)
    else:
        resolver_path = os.path.expanduser("~/.resolvers.txt")
        if not os.path.exists(resolver_path):
            print(f"{colors.YELLOW}⚠️ No resolvers.txt, using defaults{colors.RESET}")
            resolver_path = "8.8.8.8,1.1.1.1"

    command = (
        f"shuffledns -l {subdomains_file} "
        f"-r {resolver_path} "
        f"-mode resolve "
        f"-sw {domain} "
        f"| dnsx -silent -t 10 -rl 30 -resp -json"
    )

    print(f"{colors.GRAY}Executing command: {command}{colors.RESET}")
    results = run_command_in_bash(command)

    try:
        os.unlink(subdomains_file)
    except Exception:
        pass

    if not results:
        return []

    parsed_results = []
    for line in results:
        line = line.strip()
        if not line:
            continue
        try:
            parsed_results.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    print(f"{colors.GREEN}✅ Resolved {len(parsed_results)} live hosts{colors.RESET}")
    return parsed_results


def save_dns_output(program_name: str, domain: str, results: list,
                    scope=None, oos=None):
    """Save DNS scan log to dns.json (OOS hosts filtered)."""
    scope = scope or []
    oos = oos or []
    safe_name = sanitize_name(program_name)
    dns_dir = DATABASE_DIR / safe_name / "dns"
    output_file = dns_dir / "dns.json"
    dns_dir.mkdir(parents=True, exist_ok=True)

    existing_data = {"scans": []}
    if output_file.exists():
        try:
            with output_file.open("r", encoding="utf-8") as f:
                existing_data = json.load(f)
        except (json.JSONDecodeError, Exception):
            existing_data = {"scans": []}

    scan_entry = {
        "timestamp": current_time(),
        "domain": domain,
        "source": "dnsx+shuffledns",
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
    existing_data["scans"].append(scan_entry)

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(existing_data, f, indent=4, ensure_ascii=False)

    print(f"{colors.GREEN}💾 DNS scan saved to {output_file}{colors.RESET}")


def save_lives(program_name: str, domain: str, results: list,
               scope=None, oos=None):
    """
    Update lives.json with liveness tracking (scope-enforced).

      - existing entries matching OOS are purged
      - fresh results matching OOS are skipped
      - Resolved hosts   → status="alive", last_seen updated.
      - Was alive, gone  → status="dead", died_at set, subdomain_dead change.
      - Was dead, back   → status="alive", subdomain_revived change.
    """
    scope = scope or []
    oos = oos or []
    safe_name = sanitize_name(program_name)
    dns_dir = DATABASE_DIR / safe_name / "dns"
    lives_file = dns_dir / "lives.json"
    dns_dir.mkdir(parents=True, exist_ok=True)

    existing_lives = {}
    if lives_file.exists():
        try:
            with lives_file.open("r", encoding="utf-8") as f:
                existing_lives = json.load(f)
        except (json.JSONDecodeError, Exception):
            existing_lives = {}

    # Purge stale OOS entries
    if scope or oos:
        before = len(existing_lives)
        existing_lives = {
            k: v for k, v in existing_lives.items()
            if is_in_scope(k, scope, oos)
        }
        removed = before - len(existing_lives)
        if removed:
            print(f"{colors.YELLOW}⏭  {removed} host(s) removed (out of scope){colors.RESET}")

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
            print(f"{colors.GRAY}⏭  {host} (out of scope){colors.RESET}")
            continue
        resolved_hosts.add(host)

        old = existing_lives.get(host, {})
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

        existing_lives[host] = current

    # 2. Mark previously-alive hosts as dead (per this domain only)
    dead_count = 0
    for host, info in existing_lives.items():
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
        json.dump(existing_lives, f, indent=4, ensure_ascii=False)

    if new_count:
        print(f"{colors.GREEN}🆕 {new_count} new live hosts added{colors.RESET}")
    if revived_count:
        print(f"{colors.GREEN}♻️  {revived_count} revived{colors.RESET}")
    if dead_count:
        print(f"{colors.RED}💀 {dead_count} marked dead{colors.RESET}")
    alive_total = sum(1 for i in existing_lives.values() if i.get("status") == "alive")
    print(f"{colors.CYAN}📋 Total live: {alive_total} "
          f"(dead: {len(existing_lives) - alive_total}){colors.RESET}")


# =========================
# Main
# =========================

if __name__ == "__main__":
    raw_input = sys.argv[1] if len(sys.argv) > 1 else False

    if raw_input is False:
        print("Usage: python3 watch_dns.py <scope_name | URL>")
        sys.exit(1)

    domain = extract_domain(raw_input)
    if raw_input != domain:
        print(f"{colors.GRAY}Input: {raw_input}{colors.RESET}")
        print(f"{colors.GRAY}Extracted domain: {domain}{colors.RESET}")

    program = find_program_by_scope(domain)
    if not program:
        print(f"{colors.RED}[{current_time()}] domain '{domain}' not found{colors.RESET}")
        sys.exit(1)

    program_name = program.get("program_name", "unknown")
    safe_name = sanitize_name(program_name)
    scope, oos = load_scope_from_path(DATABASE_DIR / safe_name / "program.json")

    print(f"{colors.CYAN}[{current_time()}] running DNS module for '{domain}'{colors.RESET}")
    print(f"{colors.CYAN}📦 Program: {program_name}{colors.RESET}")
    if oos:
        print(f"{colors.CYAN}🚫 OOS    : {', '.join(oos)}{colors.RESET}")

    subdomains = get_subdomains(program_name, domain)
    if not subdomains:
        print(f"{colors.YELLOW}[{current_time()}] No subdomains to resolve.{colors.RESET}")
        sys.exit(0)

    dns_results = run_dnsx(subdomains, domain)
    if not dns_results:
        print(f"{colors.YELLOW}[{current_time()}] No live hosts found for {domain}{colors.RESET}")
        save_dns_output(program_name, domain, [], scope=scope, oos=oos)
        save_lives(program_name, domain, [], scope=scope, oos=oos)
        sys.exit(0)

    save_dns_output(program_name, domain, dns_results, scope=scope, oos=oos)
    save_lives(program_name, domain, dns_results, scope=scope, oos=oos)

    print(f"\n{colors.GREEN}{'='*50}{colors.RESET}")
    print(f"{colors.GREEN}✅ DNS scan completed for {domain}{colors.RESET}")
    print(f"{colors.GREEN}   Program: {program_name}{colors.RESET}")
    print(f"{colors.GREEN}   Live hosts: {len(dns_results)}{colors.RESET}")
    print(f"{colors.GREEN}{'='*50}{colors.RESET}")