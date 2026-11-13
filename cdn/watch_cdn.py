#!/usr/bin/env python3
"""
WatchTower - CDN / Cloud / WAF Detection (cdncheck)

Reads IPs from database/<program>/dns/lives.json, asks cdncheck
whether each IP belongs to a CDN/Cloud/WAF, and reports.

Writes:
  database/<program>/cdn/cdn.json
  database/<program>/cdn/lives-cdn.json

Usage:
  python3 watch_cdn.py <domain>
"""

import sys
import json
import subprocess
import tempfile
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
# Configuration
# =========================

CDNCHECK_UPDATE_TIMEOUT = 180
CDNCHECK_TIMEOUT = 120
CDNCHECK_THREADS = 50


# =========================
# Module-level state
# =========================

_cdncheck_updated = None


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
        except Exception:
            continue
        scopes = data.get("scope", []) + data.get("ooscope", [])
        for scope in scopes:
            clean = scope.lstrip("*.").lower()
            if scope_name == clean or scope_name.endswith("." + clean):
                return data
    return None


def update_cdncheck() -> bool:
    global _cdncheck_updated

    if _cdncheck_updated is not None:
        return _cdncheck_updated

    print(f"     {colors.GRAY}Running: cdncheck -up{colors.RESET}")

    try:
        result = subprocess.run(
            ["cdncheck", "-up"],
            capture_output=True,
            text=True,
            timeout=CDNCHECK_UPDATE_TIMEOUT,
        )
        if result.returncode == 0:
            print(f"     {colors.GREEN}✅ cdncheck updated{colors.RESET}")
            _cdncheck_updated = True
            return True
        stderr = result.stderr.strip()
        if stderr:
            for line in stderr.splitlines()[:3]:
                print(f"     {colors.YELLOW}{line[:150]}{colors.RESET}")
    except FileNotFoundError:
        print(f"{colors.RED}❌ cdncheck not found. Install: go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest{colors.RESET}")
        _cdncheck_updated = False
        return False
    except subprocess.TimeoutExpired:
        print(f"     {colors.YELLOW}⏰ cdncheck update timeout after {CDNCHECK_UPDATE_TIMEOUT}s{colors.RESET}")
    except Exception as e:
        print(f"     {colors.RED}❌ cdncheck update error: {e}{colors.RESET}")

    print(f"     {colors.YELLOW}⚠️ cdncheck update failed, using built-in ranges (-duc){colors.RESET}")
    _cdncheck_updated = False
    return False


def run_cdncheck(ips: list) -> dict:
    """
    Send IPs to cdncheck. Returns {ip: {cdn, cdn_name, cloud, cloud_name, waf, waf_name}}.
    """
    if not ips:
        return {}

    update_ok = update_cdncheck()

    unique_ips = sorted(set(ip.strip() for ip in ips if ip.strip()))
    if not unique_ips:
        return {}

    with tempfile.TemporaryDirectory(prefix="wt_cdncheck_") as tmpdir:
        tmp = Path(tmpdir)
        ips_file = tmp / "ips.txt"
        out_file = tmp / "cdncheck.jsonl"

        ips_file.write_text("\n".join(unique_ips) + "\n", encoding="utf-8")

        command = [
            "cdncheck",
            "-i", str(ips_file),
            "-jsonl",
            "-silent",
            "-t", str(CDNCHECK_THREADS),
            "-o", str(out_file),
        ]
        if not update_ok:
            command.append("-duc")

        print(f"     {colors.GRAY}Running: cdncheck -i ips.txt -jsonl -silent -t {CDNCHECK_THREADS}"
              f"{' -duc' if not update_ok else ''}{colors.RESET}")
        print(f"     {colors.GRAY}Checking {len(unique_ips)} IP(s){colors.RESET}")

        try:
            subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=CDNCHECK_TIMEOUT,
            )
        except FileNotFoundError:
            print(f"{colors.RED}❌ cdncheck not found{colors.RESET}")
            return {}
        except subprocess.TimeoutExpired:
            print(f"     {colors.YELLOW}⏰ cdncheck timeout after {CDNCHECK_TIMEOUT}s{colors.RESET}")
            return {}
        except Exception as e:
            print(f"     {colors.RED}❌ cdncheck error: {e}{colors.RESET}")
            return {}

        if not out_file.exists():
            print(f"     {colors.YELLOW}⚠️ cdncheck produced no output{colors.RESET}")
            return {}

        results = {}
        try:
            with out_file.open("r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    ip = obj.get("ip") or obj.get("input", "")
                    if not ip:
                        continue
                    results[ip] = {
                        "cdn": bool(obj.get("cdn", False)),
                        "cdn_name": obj.get("cdn_name", "") or "",
                        "cloud": bool(obj.get("cloud", False)),
                        "cloud_name": obj.get("cloud_name", "") or "",
                        "waf": bool(obj.get("waf", False)),
                        "waf_name": obj.get("waf_name", "") or "",
                    }
        except Exception as e:
            print(f"     {colors.RED}❌ Could not parse cdncheck output: {e}{colors.RESET}")
            return {}

    return results


# =========================
# Save
# =========================

def save_cdn_results(program_name: str, domain: str, hosts: list):
    safe = sanitize_name(program_name)
    cdn_dir = DATABASE_DIR / safe / "cdn"
    cdn_dir.mkdir(parents=True, exist_ok=True)
    ts = current_time()

    # cdn.json (scan log)
    log_file = cdn_dir / "cdn.json"
    existing = {"scans": []}
    if log_file.exists():
        try:
            existing = json.loads(log_file.read_text(encoding="utf-8"))
        except Exception:
            pass
    existing["scans"].append({
        "timestamp": ts,
        "domain": domain,
        "program_name": program_name,
        "source": "cdncheck",
        "hosts_count": len(hosts),
        "hosts": hosts,
    })
    log_file.write_text(json.dumps(existing, indent=4, ensure_ascii=False), encoding="utf-8")
    print(f"     {colors.GREEN}💾 cdn.json → {log_file}{colors.RESET}")

    # lives-cdn.json (master)
    lives_file = cdn_dir / "lives-cdn.json"
    lives = {}
    if lives_file.exists():
        try:
            lives = json.loads(lives_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    new_count = 0
    for h in hosts:
        host = h["host"]
        if host not in lives:
            new_count += 1
        lives[host] = h

    lives_file.write_text(json.dumps(lives, indent=4, ensure_ascii=False), encoding="utf-8")
    if new_count:
        print(f"     {colors.GREEN}🆕 {new_count} new to lives-cdn.json{colors.RESET}")
    print(f"     {colors.CYAN}📋 lives-cdn.json: {len(lives)} total{colors.RESET}")


# =========================
# Core
# =========================

def detect_cdn(program_name: str, domain: str) -> list:
    safe = sanitize_name(program_name)
    lives_file = DATABASE_DIR / safe / "dns" / "lives.json"

    if not lives_file.exists():
        print(f"{colors.YELLOW}⚠️ No dns/lives.json for '{program_name}'{colors.RESET}")
        return []

    try:
        lives = json.loads(lives_file.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"{colors.RED}❌ Error reading dns/lives.json: {e}{colors.RESET}")
        return []

    hosts = []
    all_ips = []
    for host, info in lives.items():
        if info.get("domain") != domain:
            continue
        ips = info.get("ips", []) or []
        hosts.append({"host": host, "ips": ips})
        all_ips.extend(ips)

    if not hosts:
        print(f"{colors.YELLOW}⚠️ No hosts for {domain} in dns/lives.json{colors.RESET}")
        return []

    print(f"     {colors.CYAN}📋 Loaded {len(hosts)} host(s), {len(all_ips)} IP(s){colors.RESET}")

    ip_results = run_cdncheck(all_ips)

    ts = current_time()
    results = []
    for h in hosts:
        host = h["host"]
        ips = h["ips"]

        cdn = False
        cdn_names = set()
        cloud = False
        cloud_names = set()
        waf = False
        waf_names = set()

        for ip in ips:
            info = ip_results.get(ip, {})
            if info.get("cdn"):
                cdn = True
                if info.get("cdn_name"):
                    cdn_names.add(info["cdn_name"])
            if info.get("cloud"):
                cloud = True
                if info.get("cloud_name"):
                    cloud_names.add(info["cloud_name"])
            if info.get("waf"):
                waf = True
                if info.get("waf_name"):
                    waf_names.add(info["waf_name"])

        is_proxied = cdn or cloud or waf

        if cdn_names:
            provider = ", ".join(sorted(cdn_names))
        elif cloud_names:
            provider = ", ".join(sorted(cloud_names))
        elif waf_names:
            provider = ", ".join(sorted(waf_names))
        else:
            provider = "None"

        results.append({
            "domain": domain,
            "host": host,
            "ips": ips,
            "cdn": is_proxied,
            "provider": provider,
            "cdn_names": sorted(cdn_names),
            "cloud_names": sorted(cloud_names),
            "waf_names": sorted(waf_names),
            "last_seen": ts,
        })

    return results


# =========================
# Main
# =========================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 watch_cdn.py <domain>")
        print("")
        print("Requires: cdncheck")
        print("  go install -v github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest")
        sys.exit(1)

    domain = sys.argv[1].strip().lower().lstrip("*.")

    program = find_program_by_scope(domain)
    if not program:
        print(f"{colors.RED}[{current_time()}] scope '{domain}' does not exist{colors.RESET}")
        sys.exit(1)

    program_name = program.get("program_name", "unknown")
    print(f"{colors.CYAN}[{current_time()}] CDN/Cloud/WAF detection for '{domain}'{colors.RESET}")
    print(f"{colors.CYAN}📦 Program: {program_name}{colors.RESET}")

    results = detect_cdn(program_name, domain)

    if not results:
        print(f"{colors.YELLOW}⚠️ No results{colors.RESET}")
        sys.exit(0)

    print()
    for r in results:
        if r["cdn"]:
            tag = f"{colors.YELLOW}CDN: {r['provider']}{colors.RESET}"
        else:
            tag = f"{colors.GREEN}CDN: None{colors.RESET}"
        print(f"     {r['host']:40s} {tag}")

    proxied = sum(1 for r in results if r["cdn"])
    print()
    print(f"     {colors.CYAN}📊 {proxied}/{len(results)} behind CDN{colors.RESET}")

    save_cdn_results(program_name, domain, results)

    print(f"\n{colors.GREEN}{'='*50}{colors.RESET}")
    print(f"{colors.GREEN}✅ Detection completed{colors.RESET}")
    print(f"{colors.GREEN}   Domain: {domain}{colors.RESET}")
    print(f"{colors.GREEN}   Hosts : {len(results)}{colors.RESET}")
    print(f"{colors.GREEN}{'='*50}{colors.RESET}")