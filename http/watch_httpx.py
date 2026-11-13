#!/usr/bin/env python3
"""
WatchTower - HTTPX Module
Runs httpx on live hosts from DNS output and saves results to:
database/<program-name>/http/httpx.json
database/<program-name>/http/lives-http.json

Detects changes vs. the previous run (status, title, content hash,
webserver, tech, IPs, content length) and logs them to
database/<program-name>/changes/changes.json.

Scope enforcement:
  - out_of_scope (and legacy "ooscope") is applied to both existing
    data (purged on write) and fresh results (skipped).
  - OOS wins over scope.
"""

import sys
import subprocess
import re
import json
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
from configs.changes import (
    detect_http_changes,
    merge_host_record,
    append_to_program_log,
)
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
        m = re.search(r'(?:https?://)?([^/:\s]+)', raw_input)
        if m:
            domain = m.group(1)
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
            timeout=30,
        )
        if result.returncode != 0:
            if result.stderr.strip():
                print(f"{colors.YELLOW}Error occurred:{colors.RESET} {result.stderr[:200]}")
            return ""
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        print(f"{colors.YELLOW}⏰ Command timed out{colors.RESET}")
        return ""
    except subprocess.CalledProcessError as exc:
        print(f"{colors.RED}Status: FAIL{colors.RESET} {exc.returncode}")
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


def get_live_hosts(program_name: str, domain: str) -> list:
    safe_name = sanitize_name(program_name)
    lives_file = DATABASE_DIR / safe_name / "dns" / "lives.json"

    if not lives_file.exists():
        print(f"{colors.YELLOW}⚠️ No lives.json for '{program_name}'{colors.RESET}")
        print(f"{colors.YELLOW}   Run watch_dns.py first{colors.RESET}")
        return []

    try:
        with lives_file.open("r", encoding="utf-8") as f:
            lives = json.load(f)
    except (json.JSONDecodeError, Exception) as e:
        print(f"{colors.RED}❌ Error reading lives.json: {e}{colors.RESET}")
        return []

    scope, oos = load_scope_from_path(DATABASE_DIR / safe_name / "program.json")

    hosts = []
    oos_skipped = 0
    for host, info in lives.items():
        if info.get("domain") != domain:
            continue
        if info.get("status", "alive") != "alive":
            continue
        if (scope or oos) and not is_in_scope(host, scope, oos):
            oos_skipped += 1
            continue
        hosts.append(host)

    if oos_skipped:
        print(f"{colors.YELLOW}⏭  {oos_skipped} host(s) skipped (out of scope){colors.RESET}")

    if not hosts:
        print(f"{colors.YELLOW}⚠️ No live hosts for '{domain}'{colors.RESET}")
        return []

    print(f"{colors.CYAN}📋 Loaded {len(hosts)} live hosts for {domain}{colors.RESET}")
    return hosts


def run_httpx(hosts: list, domain: str) -> list:
    if not hosts:
        return []

    results = []
    total = len(hosts)

    for i, host in enumerate(hosts, 1):
        print(f"{colors.GRAY}[{i}/{total}] Probing: {host}{colors.RESET}")

        command = (
            f"echo {host} | httpx -silent -json -favicon -fhr -tech-detect -irh "
            f"-include-chain -timeout 5 -retries 3 -threads 5 -rate-limit 5 "
            f"-ports 443 -hash sha256 "
            f"-H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36' "
            f"-H 'Referer: https://{host}' "
        )

        output = run_command_in_bash(command)
        if not output:
            continue

        try:
            results.append(json.loads(output))
        except json.JSONDecodeError:
            print(f"{colors.YELLOW}⚠️ Invalid JSON from httpx for {host}{colors.RESET}")

    print(f"{colors.GREEN}✅ Probed {len(results)}/{total} hosts successfully{colors.RESET}")
    return results


def save_httpx_output(program_name: str, domain: str, results: list,
                      scope=None, oos=None):
    scope = scope or []
    oos = oos or []
    safe_name = sanitize_name(program_name)
    http_dir = DATABASE_DIR / safe_name / "http"
    output_file = http_dir / "httpx.json"
    http_dir.mkdir(parents=True, exist_ok=True)

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
        "source": "httpx",
        "hosts_count": 0,
        "hosts": [],
    }

    for obj in results:
        host = obj.get("host", obj.get("url", ""))
        if host and (scope or oos) and not is_in_scope(host, scope, oos):
            continue
        scan_entry["hosts"].append({
            "host": host,
            "url": obj.get("url", ""),
            "final_url": obj.get("final_url", ""),
            "ips": obj.get("a", []),
            "status_code": obj.get("status_code", ""),
            "title": obj.get("title", ""),
            "tech": obj.get("tech", []),
            "favicon": obj.get("favicon", ""),
            "hash": obj.get("hash", ""),
            "headers": obj.get("header", {}),
            "webserver": obj.get("webserver", ""),
            "content_type": obj.get("content_type", ""),
            "content_length": obj.get("content_length", ""),
        })

    scan_entry["hosts_count"] = len(scan_entry["hosts"])
    existing_data["scans"].append(scan_entry)

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(existing_data, f, indent=4, ensure_ascii=False)

    print(f"{colors.GREEN}💾 HTTPX scan saved to {output_file}{colors.RESET}")


def _load_cdn_data(program_name):
    safe = sanitize_name(program_name)
    cdn_file = DATABASE_DIR / safe / "cdn" / "lives-cdn.json"
    if not cdn_file.exists():
        return {}
    try:
        data = json.loads(cdn_file.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_lives_http(program_name: str, domain: str, results: list,
                    scope=None, oos=None):
    """
    Update lives-http.json with change detection (scope-enforced).
    OOS entries are purged from existing data and fresh results are skipped.
    """
    scope = scope or []
    oos = oos or []
    safe_name = sanitize_name(program_name)
    http_dir = DATABASE_DIR / safe_name / "http"
    lives_file = http_dir / "lives-http.json"
    http_dir.mkdir(parents=True, exist_ok=True)

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

    cdn_data = _load_cdn_data(program_name)

    new_count = 0
    changed_count = 0
    total_changes = 0

    for obj in results:
        host = obj.get("host", "") or ""
        if not host:
            url = obj.get("url", "")
            if url:
                host = urlparse(url).hostname or url
        if not host:
            continue
        if (scope or oos) and not is_in_scope(host, scope, oos):
            print(f"{colors.GRAY}⏭  {host} (out of scope){colors.RESET}")
            continue

        current = {
            "domain": domain,
            "url": obj.get("url", ""),
            "final_url": obj.get("final_url", ""),
            "status_code": obj.get("status_code", ""),
            "title": obj.get("title", ""),
            "tech": obj.get("tech", []),
            "ips": obj.get("a", []),
            "favicon": obj.get("favicon", ""),
            "hash": obj.get("hash", ""),
            "webserver": obj.get("webserver", ""),
            "content_type": obj.get("content_type", ""),
            "content_length": obj.get("content_length", ""),
        }

        old = existing_lives.get(host, {})
        is_behind_cdn = bool((cdn_data.get(host) or {}).get("cdn"))

        changes = detect_http_changes(
            old, current,
            url=current["url"],
            is_behind_cdn=is_behind_cdn,
        )

        merged = merge_host_record(old, current, changes)
        existing_lives[host] = merged

        if not old:
            new_count += 1
        if changes:
            changed_count += 1
            total_changes += len(changes)
            append_to_program_log(program_name, host, "http", changes)
            for ch in changes:
                print(f"     {colors.YELLOW}🔔 {host}: "
                      f"{ch['type']} ({ch['severity']}){colors.RESET}")

    with lives_file.open("w", encoding="utf-8") as f:
        json.dump(existing_lives, f, indent=4, ensure_ascii=False)

    if new_count:
        print(f"{colors.GREEN}🆕 {new_count} new HTTP service(s){colors.RESET}")
    if changed_count:
        print(f"{colors.YELLOW}🔄 {changed_count} host(s) changed ({total_changes} event(s)){colors.RESET}")
    print(f"{colors.CYAN}📋 Total HTTP services: {len(existing_lives)}{colors.RESET}")


# =========================
# Main
# =========================

if __name__ == "__main__":
    raw_input = sys.argv[1] if len(sys.argv) > 1 else False

    if raw_input is False:
        print("Usage: python3 watch_httpx.py <scope_name | URL>")
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

    print(f"{colors.CYAN}[{current_time()}] running HTTPX module for '{domain}'{colors.RESET}")
    print(f"{colors.CYAN}📦 Program: {program_name}{colors.RESET}")
    if oos:
        print(f"{colors.CYAN}🚫 OOS    : {', '.join(oos)}{colors.RESET}")

    hosts = get_live_hosts(program_name, domain)
    if not hosts:
        print(f"{colors.YELLOW}[{current_time()}] No live hosts to probe.{colors.RESET}")
        sys.exit(0)

    httpx_results = run_httpx(hosts, domain)
    if not httpx_results:
        print(f"{colors.YELLOW}[{current_time()}] No HTTP responses for {domain}{colors.RESET}")
        sys.exit(0)

    save_httpx_output(program_name, domain, httpx_results, scope=scope, oos=oos)
    save_lives_http(program_name, domain, httpx_results, scope=scope, oos=oos)

    print(f"\n{colors.GREEN}{'='*50}{colors.RESET}")
    print(f"{colors.GREEN}✅ HTTPX scan completed for {domain}{colors.RESET}")
    print(f"{colors.GREEN}   Program: {program_name}{colors.RESET}")
    print(f"{colors.GREEN}   Probed: {len(hosts)}, Responsive: {len(httpx_results)}{colors.RESET}")
    print(f"{colors.GREEN}{'='*50}{colors.RESET}")