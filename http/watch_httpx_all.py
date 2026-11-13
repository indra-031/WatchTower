#!/usr/bin/env python3
"""
WatchTower - HTTP All Modules
Runs httpx on all live hosts from all programs.
Reads from: database/<program>/dns/lives.json
Saves to:   database/<program>/http/httpx.json
            database/<program>/http/lives-http.json
            database/<program>/changes/changes.json    (via configs.changes)

Detects changes vs. the previous run (status, title, content hash,
webserver, tech, IPs, content length) and logs them centrally.

Scope enforcement:
  - out_of_scope (and legacy "ooscope") is applied to both existing
    data (purged on write) and fresh results (skipped before merge).
  - OOS wins over scope.
"""

import sys
import subprocess
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
# Configuration
# =========================

HTTPX_TIMEOUT_PER_HOST = 8


# =========================
# Helpers
# =========================

def current_time():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run_httpx_batch(hosts: list) -> list:
    if not hosts:
        return []

    with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt') as f:
        for host in hosts:
            f.write(f"{host}\n")
        hosts_file = f.name

    total_timeout = max(30, len(hosts) * HTTPX_TIMEOUT_PER_HOST)

    command = (
        f"httpx -l {hosts_file} "
        f"-silent -json -favicon -tech-detect "
        f"-timeout 5 -retries 1 "
        f"-ports 443 -hash sha256 "
        f"-H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        f"(KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36' "
    )

    print(f"     {colors.GRAY}Running: httpx -l hosts.txt -ports 443 -hash sha256 ...{colors.RESET}")

    try:
        result = subprocess.run(
            ["bash", "-c", command],
            capture_output=True,
            text=True,
            timeout=total_timeout,
        )

        Path(hosts_file).unlink(missing_ok=True)

        stderr = result.stderr.strip()
        if stderr:
            for line in stderr.splitlines()[:5]:
                print(f"     {colors.YELLOW}{line[:120]}{colors.RESET}")

        output = result.stdout.strip()
        if not output:
            print(f"     {colors.YELLOW}⚠️ httpx returned empty output{colors.RESET}")
            return []

        parsed = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        return parsed

    except subprocess.TimeoutExpired:
        print(f"     {colors.YELLOW}⏰ Batch timeout after {total_timeout}s{colors.RESET}")
        Path(hosts_file).unlink(missing_ok=True)
        return []
    except Exception as e:
        print(f"     {colors.RED}❌ {e}{colors.RESET}")
        Path(hosts_file).unlink(missing_ok=True)
        return []


def get_all_programs() -> list:
    """Get all programs with live hosts (scope-filtered)."""
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
        scope_list, oos_list = load_scope_from_path(program_file)

        lives_file = program_dir / "dns" / "lives.json"
        if not lives_file.exists():
            continue

        try:
            with lives_file.open("r", encoding="utf-8") as f:
                lives = json.load(f)
        except (json.JSONDecodeError, Exception):
            continue

        if not lives:
            continue

        # Group by domain, only alive + in-scope hosts
        oos_skipped = 0
        domains = {}
        for host, info in lives.items():
            if info.get("status", "alive") != "alive":
                continue
            if (scope_list or oos_list) and not is_in_scope(host, scope_list, oos_list):
                oos_skipped += 1
                continue
            domain = info.get("domain", "unknown")
            domains.setdefault(domain, []).append(host)

        if oos_skipped:
            print(f"{colors.YELLOW}⏭  {program_name}: {oos_skipped} host(s) skipped (out of scope){colors.RESET}")

        domains = {d: h for d, h in domains.items() if h}
        if not domains:
            continue

        programs.append({
            "program_name": program_name,
            "domains": domains,
            "path": program_dir,
            "scope": scope_list,
            "oos": oos_list,
        })

    return programs


def _load_cdn_data(program_path: Path) -> dict:
    cdn_file = program_path / "cdn" / "lives-cdn.json"
    if not cdn_file.exists():
        return {}
    try:
        data = json.loads(cdn_file.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def save_outputs(program_path: Path, domain: str, results: list,
                 scope=None, oos=None):
    """
    Save httpx.json (scan log) and lives-http.json (aggregated with change history).
    All detected changes are appended to database/<program>/changes/changes.json.
    OOS hosts are filtered from both writes.
    """
    scope = scope or []
    oos = oos or []
    http_dir = program_path / "http"
    http_dir.mkdir(parents=True, exist_ok=True)

    # --- httpx.json (scan log) ---
    output_file = http_dir / "httpx.json"
    existing = {"scans": []}
    if output_file.exists():
        try:
            existing = json.loads(output_file.read_text(encoding="utf-8"))
        except Exception:
            existing = {"scans": []}

    hosts_list = []
    for obj in results:
        url = obj.get("url", "")
        host = obj.get("host", "")
        if not host and url:
            host = urlparse(url).hostname or url
        if host and (scope or oos) and not is_in_scope(host, scope, oos):
            continue
        hosts_list.append({
            "host": host,
            "url": url,
            "final_url": obj.get("final_url", ""),
            "ips": obj.get("a", []),
            "status_code": obj.get("status_code", ""),
            "title": obj.get("title", ""),
            "tech": obj.get("tech", []),
            "favicon": obj.get("favicon", ""),
            "hash": obj.get("hash", ""),
            "webserver": obj.get("webserver", ""),
            "content_type": obj.get("content_type", ""),
            "content_length": obj.get("content_length", ""),
        })

    existing["scans"].append({
        "timestamp": current_time(),
        "domain": domain,
        "source": "httpx",
        "hosts_count": len(hosts_list),
        "hosts": hosts_list,
    })

    output_file.write_text(
        json.dumps(existing, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )

    # --- lives-http.json ---
    lives_file = http_dir / "lives-http.json"
    existing_lives = {}
    if lives_file.exists():
        try:
            existing_lives = json.loads(lives_file.read_text(encoding="utf-8"))
        except Exception:
            existing_lives = {}

    # Purge stale OOS entries
    if scope or oos:
        before = len(existing_lives)
        existing_lives = {k: v for k, v in existing_lives.items() if is_in_scope(k, scope, oos)}
        removed = before - len(existing_lives)
        if removed:
            print(f"     {colors.YELLOW}⏭  {removed} host(s) removed (out of scope){colors.RESET}")

    cdn_data = _load_cdn_data(program_path)
    program_name = program_path.name

    new_count = 0
    changed_count = 0
    total_changes = 0

    for obj in results:
        url = obj.get("url", "")
        host = obj.get("host", "")
        if not host and url:
            host = urlparse(url).hostname or url
        if not host:
            continue
        if (scope or oos) and not is_in_scope(host, scope, oos):
            print(f"     {colors.GRAY}⏭  {host} (out of scope){colors.RESET}")
            continue

        current = {
            "domain": domain,
            "url": url,
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
            old, current, url=url, is_behind_cdn=is_behind_cdn,
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
                print(f"     {colors.YELLOW}🔔 {host}: {ch['type']} "
                      f"({ch['severity']}){colors.RESET}")

    lives_file.write_text(
        json.dumps(existing_lives, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"     {colors.GREEN}💾 Saved{colors.RESET}")
    if new_count:
        print(f"     {colors.GREEN}🆕 {new_count} new{colors.RESET}")
    if changed_count:
        print(f"     {colors.YELLOW}🔄 {changed_count} host(s) changed "
              f"({total_changes} event(s)){colors.RESET}")
    print(f"     {colors.CYAN}📋 Total HTTP: {len(existing_lives)}{colors.RESET}")


# =========================
# Main
# =========================

if __name__ == "__main__":
    print(f"{colors.CYAN}[{current_time()}] WatchTower — HTTP All{colors.RESET}")
    print()

    programs = get_all_programs()

    if not programs:
        print(f"{colors.RED}❌ No programs with live hosts.{colors.RESET}")
        print(f"{colors.YELLOW}   Run watch_dns_all.py first.{colors.RESET}")
        sys.exit(1)

    print(f"{colors.CYAN}📦 Programs : {len(programs)}{colors.RESET}")
    print()

    for program in programs:
        program_name = program["program_name"]
        domains = program["domains"]
        scope_list = program["scope"]
        oos_list = program["oos"]

        for domain, hosts in domains.items():
            print(f"{colors.BLUE}{'─'*50}{colors.RESET}")
            print(f"{colors.BLUE}🌐 {domain} — {len(hosts)} host(s){colors.RESET}")
            if oos_list:
                print(f"{colors.BLUE}🚫 OOS: {', '.join(oos_list)}{colors.RESET}")
            print(f"{colors.BLUE}{'─'*50}{colors.RESET}")

            results = run_httpx_batch(hosts)

            if results:
                print(f"     {colors.GREEN}✅ {len(results)}/{len(hosts)} responsive{colors.RESET}")
            else:
                print(f"     {colors.YELLOW}⚠️ 0/{len(hosts)} responsive{colors.RESET}")

            save_outputs(program["path"], domain, results,
                         scope=scope_list, oos=oos_list)
            print()

    print(f"{colors.GREEN}{'='*50}{colors.RESET}")
    print(f"{colors.GREEN}✅ Complete{colors.RESET}")
    print(f"{colors.GREEN}{'='*50}{colors.RESET}")