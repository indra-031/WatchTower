#!/usr/bin/env python3
"""
WatchTower - WHOIS / RDAP Module
Queries registration data for domains and IPs via RDAP (JSON).

Saves results to:
  database/<program>/whois/whois.json         (scan log)
  database/<program>/whois/lives-whois.json   (master, keyed by target)
  database/<program>/whois/whois_done.json    (targets already queried)

Reads scopes/IPs from:
  database/<program>/program.json
  database/<program>/dns/lives.json          (preferred IP source)
  database/<program>/http/lives-http.json    (fallback IP source)

By default, targets already in whois_done.json are skipped.
Use --force to re-query everything.

Usage:
  python3 watch_whois.py <domain>
  python3 watch_whois.py <domain> --force
"""

import sys
import json
import time
import requests
from datetime import datetime
from pathlib import Path

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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

RDAP_BASE = "https://rdap.org"
REQUEST_TIMEOUT = 20
RETRIES = 2
RETRY_BACKOFF = 2
RATE_LIMIT = 0.3


# =========================
# State
# =========================

_last_request = 0.0
_session = None


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
        scopes = data.get("scope", []) + data.get("ooscope", [])
        for s in scopes:
            clean = s.lstrip("*.").lower()
            if scope_name == clean or scope_name.endswith("." + clean):
                return data
    return None


# =========================
# Done tracking
# =========================

def get_done_file(program_name):
    safe = sanitize_name(program_name)
    return DATABASE_DIR / safe / "whois" / "whois_done.json"


def load_done(program_name):
    f = get_done_file(program_name)
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_done(program_name, done):
    f = get_done_file(program_name)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(done, indent=4, ensure_ascii=False), encoding="utf-8")


def target_key(ttype, value):
    return f"{ttype}:{value}"


def mark_done_in_memory(done, ttype, value, status="ok"):
    done[target_key(ttype, value)] = {
        "timestamp": current_time(),
        "status": status,
    }


# =========================
# HTTP session
# =========================

def get_session():
    global _session
    if _session is None:
        _session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=5, pool_maxsize=5, max_retries=0
        )
        _session.mount("https://", adapter)
        _session.mount("http://", adapter)
        _session.headers.update({
            "Accept": "application/rdap+json, application/json",
            "User-Agent": "WatchTower/1.0 (+https://github.com/watchtower)",
        })
    return _session


def respect_rate_limit():
    global _last_request
    elapsed = time.time() - _last_request
    if elapsed < RATE_LIMIT:
        time.sleep(RATE_LIMIT - elapsed)
    _last_request = time.time()


def rdap_get(path):
    """
    GET on RDAP. Returns (data, status) where status is:
      "ok"        -> data is a dict
      "not_found" -> 404, data is None
      "error"     -> network/timeout/other, data is None
    """
    url = f"{RDAP_BASE}{path}"
    sess = get_session()

    for attempt in range(RETRIES + 1):
        respect_rate_limit()
        try:
            r = sess.get(url, timeout=REQUEST_TIMEOUT, verify=False, allow_redirects=True)
        except requests.Timeout:
            if attempt < RETRIES:
                time.sleep(RETRY_BACKOFF * (2 ** attempt))
                continue
            return None, "error"
        except requests.ConnectionError:
            if attempt < RETRIES:
                time.sleep(RETRY_BACKOFF * (2 ** attempt))
                continue
            return None, "error"
        except Exception:
            return None, "error"

        if r.status_code == 200:
            try:
                return r.json(), "ok"
            except Exception:
                return None, "error"

        if r.status_code == 404:
            return None, "not_found"

        if r.status_code == 429:
            wait = 5
            try:
                wait = int(r.headers.get("Retry-After", 5))
            except Exception:
                pass
            time.sleep(wait)
            continue

        if 500 <= r.status_code < 600 and attempt < RETRIES:
            time.sleep(RETRY_BACKOFF * (2 ** attempt))
            continue

        return None, "error"

    return None, "error"


# =========================
# Domain parsing
# =========================

def parse_domain_rdap(data):
    if not isinstance(data, dict):
        return {}

    out = {
        "ldh_name": data.get("ldhName", ""),
        "status": data.get("status", []),
        "registrar": "",
        "registrar_id": "",
        "registrar_abuse_email": "",
        "events": {},
        "nameservers": [],
        "dnssec": bool(data.get("secureDNS", {}).get("delegationSigned", False)),
        "raw_entities_count": len(data.get("entities", [])),
    }

    for event in data.get("events", []) or []:
        action = (event.get("eventAction") or "").strip()
        date = (event.get("eventDate") or "").strip()
        if action and date:
            out["events"][action] = date

    for ns in data.get("nameservers", []) or []:
        name = (ns.get("ldhName") or "").strip().lower()
        if name:
            out["nameservers"].append(name)
    out["nameservers"] = sorted(set(out["nameservers"]))

    for entity in data.get("entities", []) or []:
        roles = entity.get("roles", []) or []
        if "registrar" not in roles:
            continue

        vcard = entity.get("vcardArray", [])
        if isinstance(vcard, list) and len(vcard) > 1:
            for item in vcard[1]:
                if not isinstance(item, list) or len(item) < 4:
                    continue
                field = item[0]
                value = item[3]
                if field == "fn" and isinstance(value, str):
                    out["registrar"] = value
                elif field == "email" and isinstance(value, str):
                    out["registrar_abuse_email"] = value
        if not out["registrar_id"]:
            out["registrar_id"] = entity.get("handle", "") or ""
        if out["registrar"]:
            break

    return out


# =========================
# IP parsing
# =========================

def parse_ip_rdap(data):
    if not isinstance(data, dict):
        return {}

    out = {
        "handle": data.get("handle", ""),
        "start_address": data.get("startAddress", ""),
        "end_address": data.get("endAddress", ""),
        "ip_version": data.get("ipVersion", ""),
        "name": data.get("name", ""),
        "type": data.get("type", ""),
        "country": data.get("country", ""),
        "parent_handle": data.get("parentHandle", ""),
        "asn": "",
        "asn_description": "",
    }

    for entity in data.get("entities", []) or []:
        roles = entity.get("roles", []) or []
        if not any(r in roles for r in ("registrant", "technical", "abuse")):
            continue

        for pub in entity.get("publicIds", []) or []:
            if (pub.get("type") or "").upper() == "IANA":
                handle = pub.get("identifier", "")
                if handle and not out["asn"]:
                    out["asn"] = handle
                    out["asn_description"] = entity.get("handle", "") or ""

        if out["asn"]:
            break

    return out


# =========================
# Core
# =========================

def query_domain(domain):
    """Returns (parsed_dict_or_None, status)."""
    data, status = rdap_get(f"/domain/{domain}")
    if status != "ok":
        return None, status
    if not data:
        return None, "error"
    parsed = parse_domain_rdap(data)
    parsed["timestamp"] = current_time()
    parsed["source"] = "rdap"
    parsed["target"] = domain
    parsed["target_type"] = "domain"
    return parsed, "ok"


def query_ip(ip):
    """Returns (parsed_dict_or_None, status)."""
    data, status = rdap_get(f"/ip/{ip}")
    if status != "ok":
        return None, status
    if not data:
        return None, "error"
    parsed = parse_ip_rdap(data)
    parsed["timestamp"] = current_time()
    parsed["source"] = "rdap"
    parsed["target"] = ip
    parsed["target_type"] = "ip"
    return parsed, "ok"


def collect_targets(program_name, domain):
    """
    Build targets for ONE specific domain:
      - the domain itself (only if it appears in scope)
      - IPs of hosts under this domain, from dns/lives.json (preferred)
        or http/lives-http.json (fallback)

    Returns a list of (type, value) tuples.
    """
    safe = sanitize_name(program_name)
    prog_file = DATABASE_DIR / safe / "program.json"

    domain = domain.strip().lower().lstrip("*.")

    targets = []
    seen = set()

    # 1) the domain itself (only if it's in scope)
    prog = load_json(prog_file)
    normalized_scopes = [
        s.strip().lstrip("*.").lower()
        for s in prog.get("scope", [])
        if s and s.strip()
    ]
    if domain in normalized_scopes:
        targets.append(("domain", domain))
        seen.add(("domain", domain))

    # 2) IPs from dns/lives.json and http/lives-http.json
    for ip_source in [
        DATABASE_DIR / safe / "dns" / "lives.json",
        DATABASE_DIR / safe / "http" / "lives-http.json",
    ]:
        if not ip_source.exists():
            continue
        data = load_json(ip_source)
        for host, info in data.items():
            if info.get("domain") != domain:
                continue
            for ip in info.get("ips", []) or []:
                ip = ip.strip()
                if not ip:
                    continue
                key = ("ip", ip)
                if key not in seen:
                    seen.add(key)
                    targets.append(key)

    return targets


def save_results(program_name, domain, results):
    safe = sanitize_name(program_name)
    whois_dir = DATABASE_DIR / safe / "whois"
    whois_dir.mkdir(parents=True, exist_ok=True)
    ts = current_time()

    # whois.json (scan log)
    log_file = whois_dir / "whois.json"
    existing = load_json(log_file)
    if not isinstance(existing, dict) or "scans" not in existing:
        existing = {"scans": []}
    existing["scans"].append({
        "timestamp": ts,
        "domain": domain,
        "program_name": program_name,
        "source": "rdap",
        "results_count": len(results),
        "results": results,
    })
    save_json(log_file, existing)
    print(f"     {colors.GREEN}💾 whois.json → {log_file}{colors.RESET}")

    # lives-whois.json (master keyed by target)
    lives_file = whois_dir / "lives-whois.json"
    lives = load_json(lives_file)

    new_count = 0
    for r in results:
        key = f"{r['target_type']}:{r['target']}"
        if key not in lives:
            new_count += 1
        lives[key] = {
            "domain": domain,
            "target": r["target"],
            "target_type": r["target_type"],
            "last_seen": ts,
            "data": {k: v for k, v in r.items()
                     if k not in ("timestamp", "source", "target", "target_type")},
        }

    save_json(lives_file, lives)
    if new_count:
        print(f"     {colors.GREEN}🆕 {new_count} new in lives-whois.json{colors.RESET}")
    print(f"     {colors.CYAN}📋 lives-whois.json: {len(lives)} total{colors.RESET}")


# =========================
# Main
# =========================

if __name__ == "__main__":
    args = sys.argv[1:]
    force = "--force" in args
    non_flags = [a for a in args if not a.startswith("--")]

    if not non_flags:
        print("Usage: python3 watch_whois.py <domain> [--force]")
        print("Example: python3 watch_whois.py example.com")
        print("")
        print("Options:")
        print("  --force   re-query even targets already in whois_done.json")
        print("")
        print("Note: use watch_whois_all.py to run on all programs.")
        sys.exit(1)

    domain = non_flags[0].strip().lower().lstrip("*.")

    program = find_program_by_scope(domain)
    if not program:
        print(f"{colors.RED}[{current_time()}] scope '{domain}' does not exist{colors.RESET}")
        sys.exit(1)

    program_name = program.get("program_name", "unknown")
    print(f"{colors.CYAN}[{current_time()}] WHOIS/RDAP for '{domain}'{colors.RESET}")
    print(f"{colors.CYAN}📦 Program: {program_name}{colors.RESET}")

    targets = collect_targets(program_name, domain)
    if not targets:
        print(f"{colors.YELLOW}⚠️ No targets to query for {domain}{colors.RESET}")
        sys.exit(0)

    print(f"     {colors.CYAN}📋 {len(targets)} target(s) "
          f"({sum(1 for t, _ in targets if t == 'domain')} domains, "
          f"{sum(1 for t, _ in targets if t == 'ip')} IPs){colors.RESET}")

    # Filter by done
    done = load_done(program_name)
    if not force:
        pending = [(t, v) for t, v in targets if target_key(t, v) not in done]
        skipped = len(targets) - len(pending)
        if skipped:
            print(f"     {colors.GRAY}⏭  {skipped} already queried, "
                  f"{len(pending)} pending{colors.RESET}")
        if not pending:
            print(f"{colors.GREEN}✅ All targets already queried for {domain}{colors.RESET}")
            print(f"{colors.GRAY}   Use --force to re-query.{colors.RESET}")
            sys.exit(0)
        targets = pending

    results = []
    for i, (ttype, value) in enumerate(targets, 1):
        print(f"     {colors.GRAY}[{i}/{len(targets)}] {ttype}: {value}{colors.RESET}")

        if ttype == "domain":
            res, status = query_domain(value)
        else:
            res, status = query_ip(value)

        if status == "ok" and res:
            results.append(res)
            mark_done_in_memory(done, ttype, value, "ok")
            if ttype == "domain":
                print(f"       {colors.GREEN}✅ registrar: "
                      f"{res.get('registrar') or 'N/A'} | "
                      f"expires: {res.get('events', {}).get('expiration', 'N/A')}{colors.RESET}")
            else:
                print(f"       {colors.GREEN}✅ {res.get('name') or res.get('handle') or 'N/A'} | "
                      f"ASN: {res.get('asn') or 'N/A'}{colors.RESET}")
        elif status == "not_found":
            mark_done_in_memory(done, ttype, value, "not_found")
            print(f"       {colors.YELLOW}⚠️ No RDAP record (not_found){colors.RESET}")
        else:
            print(f"       {colors.RED}❌ Query failed (will retry next run){colors.RESET}")

    save_done(program_name, done)

    if not results:
        print(f"\n{colors.YELLOW}⚠️ No RDAP data retrieved.{colors.RESET}")
        sys.exit(0)

    save_results(program_name, domain, results)

    print(f"\n{colors.GREEN}{'='*50}{colors.RESET}")
    print(f"{colors.GREEN}✅ WHOIS/RDAP complete for '{domain}'{colors.RESET}")
    print(f"{colors.GREEN}   Queried: {len(targets)} | Results: {len(results)}{colors.RESET}")
    print(f"{colors.GREEN}{'='*50}{colors.RESET}")