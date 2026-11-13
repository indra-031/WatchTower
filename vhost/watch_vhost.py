#!/usr/bin/env python3
"""
WatchTower - Virtual Host Discovery
Discovers virtual hosts on non-CDN HTTP hosts by fuzzing the Host header.

Host header candidates come from:
  - Static wordlist (wordlist/vhost/vhost.txt + custom-vhost.txt)
  - Every subdomain in database/<program>/enum-output/all-subdomains.json
  - Prefix parts of those subdomains

Hosts behind a CDN and IPs that are not globally routable are skipped.
For mixed hosts (some public + some private IPs), only public IPs are tested.

Scope enforcement:
  - out_of_scope (and legacy "ooscope") is applied to targets, candidates,
    fresh findings, and existing lives-vhost.json. OOS wins over scope.
  - Adhoc IP mode is a manual test — scope is intentionally bypassed there.

Already-tested (host, ip) pairs are recorded in vhost/vhost_done.json
and skipped on subsequent runs unless --force is used.

Two modes:
  - Domain mode: reads from http/lives-http.json + cdn/lives-cdn.json.
    Results go to database/<program>/vhost/.
  - Adhoc mode : input is an IP. Skips database entirely.
    Results go to database/_adhoc/vhost-<ip>.json.

Usage:
  python3 watch_vhost.py <domain>                     # domain mode
  python3 watch_vhost.py <domain> --force             # re-test everything
  python3 watch_vhost.py <ip>                         # adhoc, tries https:443 then http:80
  python3 watch_vhost.py <ip>:<port>                  # adhoc, tries https then http on port
  python3 watch_vhost.py http://<ip>[:port]           # adhoc, http only
  python3 watch_vhost.py https://<ip>[:port]          # adhoc, https only
  python3 watch_vhost.py --all                        # all programs
  python3 watch_vhost.py --all --force                # re-test all
  python3 watch_vhost.py <ip> --limit 50 --workers 10 # quick test
"""

import sys
import json
import random
import string
import re
import ipaddress
import requests
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# =========================
# Paths
# =========================

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_DIR = BASE_DIR / "database"
WORDLIST_DIR = BASE_DIR / "wordlist" / "vhost"

STATIC_WORDLISTS = [
    WORDLIST_DIR / "vhost.txt",
    WORDLIST_DIR / "custom-vhost.txt",
]


# =========================
# Imports from configs/
# =========================

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from configs.colors import colors
from configs.scope import load_scope_from_path, is_in_scope


# =========================
# Configuration
# =========================

BASELINE_HOST = "".join(random.choices(string.ascii_lowercase + string.digits, k=16)) + ".watchtower-baseline.local"
REQUEST_TIMEOUT = 10
VERIFY_SSL = False
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"

VALID_HOST_RE = re.compile(r'^[a-z0-9][a-z0-9._-]*$')

ADHOC_DEFAULT_WORKERS = 10
DOMAIN_DEFAULT_WORKERS = 1

PROGRESS_EVERY = 20


# =========================
# Helpers
# =========================

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize(n):
    return (n.strip().lower()
            .replace(" ", "-").replace("/", "-")
            .replace("\\", "-").replace(":", "-"))


def is_public_ip(ip_str):
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_unspecified
        or addr.is_reserved
    )


def is_valid_word(word):
    if not word:
        return False
    w = word.strip().lower()
    if len(w) < 2 or len(w) > 253:
        return False
    if "%" in w or " " in w or "/" in w or "\\" in w or "*" in w:
        return False
    for label in w.split("."):
        if not label:
            return False
        if not re.match(r'^[a-z0-9][a-z0-9_-]*$', label):
            return False
    return True


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


# =========================
# Done tracking
# =========================

def get_done_file(program_name):
    safe = sanitize(program_name)
    return DATABASE_DIR / safe / "vhost" / "vhost_done.json"


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


def target_done_key(host, ip):
    return f"{host}|{ip}"


def mark_target_done(done, host, ip):
    done[target_done_key(host, ip)] = {"tested_at": now()}


# =========================
# Wordlist / candidates
# =========================

def load_wordlists(paths):
    words = []
    for path in paths:
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue
        for line in lines:
            w = line.strip().lower()
            if not w or w.startswith("#"):
                continue
            if is_valid_word(w):
                words.append(w)
    return sorted(set(words))


def load_subdomains_for_domain(program_name, domain):
    safe = sanitize(program_name)
    all_file = DATABASE_DIR / safe / "enum-output" / "all-subdomains.json"
    if not all_file.exists():
        return []
    try:
        data = json.loads(all_file.read_text())
    except Exception:
        return []

    # Defense in depth: all-subdomains.json is already filtered at write time
    # by watch_enum_all.py, but we filter again just in case.
    prog_dir = DATABASE_DIR / safe
    scope, oos = load_scope_from_path(prog_dir / "program.json")

    subs = []
    for sub in data.keys():
        if sub == domain or sub.endswith("." + domain):
            if (scope or oos) and not is_in_scope(sub, scope, oos):
                continue
            subs.append(sub.lower())
    return sorted(set(subs))


def subdomain_prefixes(subdomain, domain):
    if not subdomain.endswith("." + domain):
        return []
    prefix = subdomain[: -(len(domain) + 1)]
    if not prefix:
        return []
    candidates = [subdomain, prefix]
    for p in prefix.split("."):
        if p and p not in candidates:
            candidates.append(p)
    return [c for c in candidates if is_valid_word(c)]


def build_host_candidates(wordlist, subdomains, domain, scope=None, oos=None):
    """
    Build Host header candidates. If scope/OOS are provided, candidates
    matching OOS are dropped. Note: candidates are hostname *prefixes*,
    not full FQDNs, so we only reject exact OOS matches here — the
    full FQDN filter happens on targets.
    """
    scope = scope or []
    oos = oos or []
    seen = set()
    result = []

    def add(x):
        if x and x not in seen and is_valid_word(x):
            if oos and x in oos:
                return
            seen.add(x)
            result.append(x)

    for w in wordlist:
        add(w)
    for sub in subdomains:
        for c in subdomain_prefixes(sub, domain):
            add(c)
    return result


# =========================
# Targets
# =========================

def load_cdn_info(prog_dir):
    for path in [
        prog_dir / "cdn" / "lives-cdn.json",
        prog_dir / "http" / "lives-waf.json",
    ]:
        if path.exists():
            try:
                return json.loads(path.read_text())
            except Exception:
                continue
    return {}


def get_targets(program_name, domain, done=None, force=False):
    """
    Targets = hosts under `domain` that are NOT behind a CDN,
    have at least one public IP, are in scope, and are not already
    in vhost_done.json (unless force=True).
    """
    safe = sanitize(program_name)
    prog_dir = DATABASE_DIR / safe
    http_file = prog_dir / "http" / "lives-http.json"
    if not http_file.exists():
        return []
    try:
        http_lives = json.loads(http_file.read_text())
    except Exception:
        return []

    cdn_lives = load_cdn_info(prog_dir)
    scope, oos = load_scope_from_path(prog_dir / "program.json")

    targets = []
    oos_skipped = 0
    for host, info in http_lives.items():
        if info.get("domain") != domain:
            continue

        if (scope or oos) and not is_in_scope(host, scope, oos):
            oos_skipped += 1
            continue

        if cdn_lives.get(host, {}).get("cdn"):
            continue

        url = info.get("url") or info.get("final_url") or f"https://{host}"
        ips = info.get("ips", []) or []

        public_ips = [ip for ip in ips if is_public_ip(ip)]
        if not public_ips:
            continue

        if done is not None and not force:
            public_ips = [
                ip for ip in public_ips
                if target_done_key(host, ip) not in done
            ]
            if not public_ips:
                continue

        targets.append({"host": host, "url": url, "ips": public_ips})

    if oos_skipped:
        print(f"     {colors.YELLOW}⏭  {oos_skipped} host(s) skipped (out of scope){colors.RESET}")

    return targets


def build_request_url(url, ip):
    parsed = urlparse(url)
    scheme = parsed.scheme or "https"
    port = parsed.port
    path = parsed.path or "/"
    netloc = ip
    if port:
        netloc = f"{ip}:{port}"
    return f"{scheme}://{netloc}{path}"


def probe(url, host_header):
    headers = {
        "Host": host_header,
        "User-Agent": USER_AGENT,
    }
    try:
        r = requests.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            verify=VERIFY_SSL,
            allow_redirects=False,
        )
        title = ""
        if "text/html" in r.headers.get("content-type", ""):
            m = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
            if m:
                title = m.group(1).strip()[:120]
        return {"status": r.status_code, "length": len(r.content), "title": title}
    except Exception:
        return None


def signature(resp):
    if not resp:
        return (None, None, None)
    return (resp["status"], resp["length"], resp["title"])


# =========================
# Concurrent probe
# =========================

def probe_candidates_concurrent(url, candidates, base_sig, workers, tag=""):
    findings = []
    total = len(candidates)
    failures = 0

    def check(c):
        r = probe(url, c)
        if r is None:
            return ("fail", None)
        if signature(r) == base_sig:
            return ("same", None)
        return ("hit", {"vhost": c, "status": r["status"],
                        "length": r["length"], "title": r["title"]})

    if workers <= 1:
        for i, c in enumerate(candidates, 1):
            if i % PROGRESS_EVERY == 0:
                print(f"     {colors.GRAY}{tag}... {i}/{total} probed, "
                      f"{len(findings)} hit(s), {failures} fail(s){colors.RESET}")
            kind, data = check(c)
            if kind == "fail":
                failures += 1
            elif kind == "hit":
                findings.append(data)
                print(f"     {colors.GREEN}   ✅ {data['vhost']} → "
                      f"status={data['status']}, len={data['length']}{colors.RESET}")
    else:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(check, c): c for c in candidates}
            done = 0
            for fut in as_completed(futures):
                done += 1
                if done % PROGRESS_EVERY == 0:
                    print(f"     {colors.GRAY}{tag}... {done}/{total} probed, "
                          f"{len(findings)} hit(s), {failures} fail(s){colors.RESET}")
                try:
                    kind, data = fut.result()
                except Exception:
                    failures += 1
                    continue
                if kind == "fail":
                    failures += 1
                elif kind == "hit":
                    findings.append(data)
                    print(f"     {colors.GREEN}   ✅ {data['vhost']} → "
                          f"status={data['status']}, len={data['length']}{colors.RESET}")

    if failures:
        print(f"     {colors.YELLOW}   ({failures}/{total} probes failed){colors.RESET}")

    return findings


# =========================
# Adhoc (IP) mode — manual test, scope intentionally bypassed
# =========================

def parse_adhoc_target(raw):
    raw = raw.strip()
    scheme = None
    port = None
    host = raw

    if "://" in raw:
        parsed = urlparse(raw)
        scheme = parsed.scheme.lower() if parsed.scheme else None
        host = parsed.hostname or ""
        port = parsed.port
    elif ":" in raw and raw.count(":") == 1:
        h, p = raw.rsplit(":", 1)
        host = h
        try:
            port = int(p)
        except Exception:
            port = None

    if not host:
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return None

    urls = []
    if scheme and port:
        urls.append((scheme, port))
    elif scheme:
        urls.append((scheme, 443 if scheme == "https" else 80))
    elif port:
        urls.append(("https", port))
        urls.append(("http", port))
    else:
        urls.append(("https", 443))
        urls.append(("http", 80))

    return {"ip": host, "urls": urls}


def run_adhoc(adhoc, workers, limit):
    ip = adhoc["ip"]
    print(f"{colors.CYAN}[{now()}] Adhoc VHost Discovery — IP {ip}{colors.RESET}")
    print(f"{colors.GRAY}   Test mode: results go to database/_adhoc/{colors.RESET}")
    print(f"{colors.GRAY}   Scope enforcement: bypassed (manual IP test){colors.RESET}\n")

    static_words = load_wordlists(STATIC_WORDLISTS)
    if not static_words:
        print(f"{colors.RED}❌ No wordlist in {WORDLIST_DIR}{colors.RESET}")
        sys.exit(1)

    candidates = list(static_words)
    if limit > 0 and limit < len(candidates):
        candidates = candidates[:limit]

    print(f"     {colors.CYAN}📋 {len(candidates)} candidate(s), workers={workers}{colors.RESET}")

    baseline = None
    findings = []
    working_url = None

    for scheme, port in adhoc["urls"]:
        url = f"{scheme}://{ip}:{port}"
        print(f"\n   {colors.CYAN}Trying {url}{colors.RESET}")

        base_resp = probe(url, BASELINE_HOST)
        if base_resp is None:
            print(f"     {colors.YELLOW}⚠️ Baseline failed, trying next URL{colors.RESET}")
            continue

        base_sig = signature(base_resp)
        title = base_resp["title"][:60] if base_resp["title"] else "-"
        print(f"     {colors.GRAY}Baseline: status={base_resp['status']}, "
              f"len={base_resp['length']}, title={title}{colors.RESET}")

        findings = probe_candidates_concurrent(url, candidates, base_sig, workers)
        baseline = base_resp
        working_url = url
        break

    if working_url is None:
        print(f"{colors.RED}❌ No working URL for {ip}{colors.RESET}")
        sys.exit(1)

    safe_ip = ip.replace(".", "-").replace(":", "-")
    adhoc_dir = DATABASE_DIR / "_adhoc"
    adhoc_dir.mkdir(parents=True, exist_ok=True)
    out_file = adhoc_dir / f"vhost-{safe_ip}.json"

    out_file.write_text(json.dumps({
        "ip": ip,
        "working_url": working_url,
        "timestamp": now(),
        "baseline": {
            "status": baseline["status"],
            "length": baseline["length"],
            "title": baseline["title"],
        },
        "candidates_count": len(candidates),
        "findings": findings,
    }, indent=4, ensure_ascii=False))

    print()
    if findings:
        print(f"     {colors.GREEN}Found {len(findings)} candidate(s) with different response:{colors.RESET}")
        for f in findings[:20]:
            line = f"       [{f['status']}] len={f['length']:<7} Host: {f['vhost']}"
            if f.get("title"):
                line += f" | {f['title'][:60]}"
            print(f"{colors.GREEN}{line}{colors.RESET}")
        if len(findings) > 20:
            print(f"       {colors.GRAY}... and {len(findings) - 20} more{colors.RESET}")
    else:
        print(f"     {colors.YELLOW}No vhost differences found (all candidates matched baseline){colors.RESET}")

    print()
    print(f"{colors.GREEN}{'='*50}{colors.RESET}")
    print(f"{colors.GREEN}✅ Adhoc discovery complete{colors.RESET}")
    print(f"{colors.GREEN}   IP:       {ip}{colors.RESET}")
    print(f"{colors.GREEN}   URL:      {working_url}{colors.RESET}")
    print(f"{colors.GREEN}   Tested:   {len(candidates)}{colors.RESET}")
    print(f"{colors.GREEN}   Findings: {len(findings)}{colors.RESET}")
    print(f"{colors.GREEN}   Saved:    {out_file}{colors.RESET}")
    print(f"{colors.GREEN}{'='*50}{colors.RESET}")


# =========================
# Domain mode
# =========================

def discover_vhosts(targets, candidates, domain, workers=1):
    findings = []
    total = len(targets)

    print(f"     {colors.CYAN}📋 {len(candidates)} Host header candidate(s) per IP "
          f"(workers={workers}){colors.RESET}")

    for idx, t in enumerate(targets, 1):
        host = t["host"]
        url = t["url"]
        ips = t["ips"]

        print(f"\n     {colors.CYAN}[{idx}/{total}] {host}{colors.RESET}")
        print(f"       IPs: {', '.join(ips)}")

        for ip in ips:
            req_url = build_request_url(url, ip)
            print(f"       Target IP: {ip} ({req_url})")

            baseline = probe(req_url, BASELINE_HOST)
            if baseline is None:
                print(f"         {colors.YELLOW}⚠️ Baseline failed, skipping IP{colors.RESET}")
                continue
            base_sig = signature(baseline)
            print(f"         Baseline: status={baseline['status']}, len={baseline['length']}")

            pair_findings = probe_candidates_concurrent(
                req_url, candidates, base_sig, workers,
                tag=f"       [{host}@{ip}]",
            )
            for f in pair_findings:
                findings.append({
                    "host": host,
                    "ip": ip,
                    "vhost": f["vhost"],
                    "status": f["status"],
                    "length": f["length"],
                    "title": f["title"],
                    "baseline_status": baseline["status"],
                    "baseline_length": baseline["length"],
                })

    return findings


def save_findings(program_name, domain, findings):
    """
    Save vhost.json (scan log) and lives-vhost.json (aggregate).
    OOS entries are purged from lives-vhost.json and fresh findings
    matching OOS are skipped.
    """
    safe = sanitize(program_name)
    vhost_dir = DATABASE_DIR / safe / "vhost"
    vhost_dir.mkdir(parents=True, exist_ok=True)
    ts = now()

    scope, oos = load_scope_from_path(DATABASE_DIR / safe / "program.json")

    # Filter fresh findings by scope/OOS
    if scope or oos:
        before = len(findings)
        findings = [f for f in findings if is_in_scope(f["vhost"], scope, oos)]
        dropped = before - len(findings)
        if dropped:
            print(f"     {colors.YELLOW}⏭  {dropped} finding(s) filtered (out of scope){colors.RESET}")

    # vhost.json (log)
    log_file = vhost_dir / "vhost.json"
    existing = {"scans": []}
    if log_file.exists():
        try:
            existing = json.loads(log_file.read_text())
        except Exception:
            pass
    existing["scans"].append({
        "timestamp": ts,
        "domain": domain,
        "program_name": program_name,
        "source": "vhost-discovery",
        "findings_count": len(findings),
        "findings": findings,
    })
    log_file.write_text(json.dumps(existing, indent=4, ensure_ascii=False))
    print(f"\n     {colors.GREEN}💾 vhost.json → {log_file}{colors.RESET}")

    # lives-vhost.json (aggregate)
    lives_file = vhost_dir / "lives-vhost.json"
    lives = {}
    if lives_file.exists():
        try:
            lives = json.loads(lives_file.read_text())
        except Exception:
            lives = {}

    # Purge stale OOS entries from lives
    if scope or oos:
        before = len(lives)
        lives = {k: v for k, v in lives.items() if is_in_scope(v.get("vhost", ""), scope, oos)}
        removed = before - len(lives)
        if removed:
            print(f"     {colors.YELLOW}⏭  {removed} stale vhost(s) removed (out of scope){colors.RESET}")

    new_count = 0
    for f in findings:
        key = f"{f['vhost']} @ {f['ip']}"
        if key not in lives:
            new_count += 1
        lives[key] = {
            "host": f["host"],
            "ip": f["ip"],
            "vhost": f["vhost"],
            "domain": domain,
            "status": f["status"],
            "length": f["length"],
            "title": f["title"],
            "last_seen": ts,
        }

    lives_file.write_text(json.dumps(lives, indent=4, ensure_ascii=False))
    if new_count:
        print(f"     {colors.GREEN}🆕 {new_count} new vhost(s) in lives-vhost.json{colors.RESET}")
    print(f"     {colors.CYAN}📋 lives-vhost.json: {len(lives)} total{colors.RESET}")


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
            progs.append({"name": data.get("program_name", d.name), "path": d})
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

    workers = None
    limit = 0
    positional = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--workers" and i + 1 < len(args):
            try:
                workers = int(args[i + 1])
            except ValueError:
                pass
            i += 2
        elif a == "--limit" and i + 1 < len(args):
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

    target = positional[0] if positional else None

    # Adhoc mode (IP input, not --all) — scope bypassed
    if not all_mode and target:
        adhoc = parse_adhoc_target(target)
        if adhoc:
            if workers is None:
                workers = ADHOC_DEFAULT_WORKERS
            run_adhoc(adhoc, workers, limit)
            sys.exit(0)

    # Domain mode
    if workers is None:
        workers = DOMAIN_DEFAULT_WORKERS

    static_words = load_wordlists(STATIC_WORDLISTS)
    if static_words:
        print(f"{colors.CYAN}📋 Static wordlist: {len(static_words)} entries{colors.RESET}")
    else:
        print(f"{colors.YELLOW}⚠️ No static wordlist, continuing with subdomains only{colors.RESET}")

    if all_mode:
        print(f"{colors.CYAN}[{now()}] WatchTower — VHost Discovery (All){colors.RESET}\n")
        progs = get_all_programs()
        if not progs:
            print(f"{colors.RED}❌ No programs found.{colors.RESET}")
            sys.exit(1)

        total_findings = 0
        total_tested = 0
        total_skipped = 0

        for prog in progs:
            pn = prog["name"]
            pd = prog["path"]
            try:
                pdata = json.loads((pd / "program.json").read_text())
                scopes = [s.strip() for s in pdata.get("scope", []) if s.strip()]
                oos_list = (
                    pdata.get("out_of_scope")
                    or pdata.get("ooscope")
                    or []
                )
            except Exception:
                continue

            done = load_done(pn)
            prog_dir = DATABASE_DIR / sanitize(pn)
            scope, oos = load_scope_from_path(prog_dir / "program.json")

            for scope_name in scopes:
                full_targets = get_targets(pn, scope_name, done=None, force=True)
                targets = get_targets(pn, scope_name, done=done, force=force)

                if not full_targets:
                    print(f"{colors.YELLOW}⚠️ No non-CDN, public-IP targets for {scope_name}{colors.RESET}")
                    continue

                skipped_pairs = sum(len(t["ips"]) for t in full_targets) - sum(len(t["ips"]) for t in targets)
                if skipped_pairs:
                    total_skipped += skipped_pairs

                if not targets:
                    print(f"{colors.GREEN}✅ All (host, ip) pairs for {scope_name} already tested{colors.RESET}")
                    if skipped_pairs:
                        print(f"     {colors.GRAY}⏭  {skipped_pairs} skipped (already done){colors.RESET}")
                    continue

                subs = load_subdomains_for_domain(pn, scope_name)
                candidates = build_host_candidates(static_words, subs, scope_name,
                                                   scope=scope, oos=oos)

                if not candidates:
                    print(f"{colors.YELLOW}⚠️ No Host header candidates for {scope_name}{colors.RESET}")
                    continue

                print(f"{colors.BLUE}🎯 {pn} — {scope_name}{colors.RESET}")
                print(f"   {len(targets)} target host(s), {len(subs)} subdomain(s), "
                      f"{len(candidates)} candidate(s)")
                if oos:
                    print(f"   {colors.BLUE}🚫 OOS: {', '.join(oos)}{colors.RESET}")
                if skipped_pairs:
                    print(f"   {colors.GRAY}⏭  {skipped_pairs} (host, ip) pair(s) skipped{colors.RESET}")

                findings = discover_vhosts(targets, candidates, scope_name, workers=workers)

                for t in targets:
                    for ip in t["ips"]:
                        mark_target_done(done, t["host"], ip)
                save_done(pn, done)

                if findings:
                    save_findings(pn, scope_name, findings)
                    total_findings += len(findings)
                else:
                    print(f"{colors.YELLOW}⚠️ No vhosts found for {scope_name}{colors.RESET}")
                total_tested += sum(len(t["ips"]) for t in targets)
                print()

        print(f"{colors.GREEN}{'='*50}{colors.RESET}")
        print(f"{colors.GREEN}✅ VHost discovery complete{colors.RESET}")
        print(f"{colors.GREEN}   Tested  : {total_tested} (host, ip) pair(s){colors.RESET}")
        if total_skipped:
            print(f"{colors.CYAN}   Skipped : {total_skipped} (already done){colors.RESET}")
        print(f"{colors.GREEN}   Findings: {total_findings}{colors.RESET}")
        print(f"{colors.GRAY}   Done files: database/<program>/vhost/vhost_done.json{colors.RESET}")
        print(f"{colors.GREEN}{'='*50}{colors.RESET}")

    elif target:
        program = find_program_by_scope(target)
        if not program:
            print(f"{colors.RED}❌ Scope '{target}' not found.{colors.RESET}")
            sys.exit(1)

        program_name = program.get("program_name", "unknown")
        prog_dir = DATABASE_DIR / sanitize(program_name)
        scope, oos = load_scope_from_path(prog_dir / "program.json")

        print(f"{colors.CYAN}[{now()}] VHost Discovery for '{target}'{colors.RESET}")
        print(f"{colors.CYAN}📦 Program: {program_name}{colors.RESET}")
        if oos:
            print(f"{colors.CYAN}🚫 OOS    : {', '.join(oos)}{colors.RESET}")

        done = load_done(program_name)

        full_targets = get_targets(program_name, target, done=None, force=True)
        targets = get_targets(program_name, target, done=done, force=force)

        if not full_targets:
            print(f"{colors.YELLOW}⚠️ No non-CDN, public-IP targets for {target}{colors.RESET}")
            sys.exit(0)

        skipped_pairs = sum(len(t["ips"]) for t in full_targets) - sum(len(t["ips"]) for t in targets)
        if skipped_pairs:
            print(f"     {colors.GRAY}⏭  {skipped_pairs} (host, ip) pair(s) already done{colors.RESET}")

        if not targets:
            print(f"{colors.GREEN}✅ All targets for {target} already tested{colors.RESET}")
            print(f"{colors.GRAY}   Use --force to re-test.{colors.RESET}")
            sys.exit(0)

        subs = load_subdomains_for_domain(program_name, target)
        candidates = build_host_candidates(static_words, subs, target,
                                           scope=scope, oos=oos)

        print(f"     {colors.CYAN}📋 {len(targets)} target host(s){colors.RESET}")
        print(f"     {colors.CYAN}📋 {len(subs)} known subdomain(s){colors.RESET}")
        print(f"     {colors.CYAN}📋 {len(candidates)} total Host header candidate(s){colors.RESET}")

        if not candidates:
            print(f"{colors.YELLOW}⚠️ No Host header candidates.{colors.RESET}")
            sys.exit(0)

        findings = discover_vhosts(targets, candidates, target, workers=workers)

        for t in targets:
            for ip in t["ips"]:
                mark_target_done(done, t["host"], ip)
        save_done(program_name, done)

        if not findings:
            print(f"\n{colors.YELLOW}⚠️ No virtual hosts discovered.{colors.RESET}")
            sys.exit(0)

        save_findings(program_name, target, findings)
        print(f"\n{colors.GREEN}✅ Done | {len(findings)} finding(s){colors.RESET}")

    else:
        print("Usage:")
        print("  python3 watch_vhost.py <domain> [--force]")
        print("  python3 watch_vhost.py <ip>[:port]                  # adhoc test")
        print("  python3 watch_vhost.py http://<ip>[:port]           # adhoc, http only")
        print("  python3 watch_vhost.py https://<ip>[:port]          # adhoc, https only")
        print("  python3 watch_vhost.py --all [--force]")
        print("")
        print("Options:")
        print("  --force       re-test (host, ip) pairs already in vhost_done.json")
        print("  --workers N   concurrent probes (adhoc default: 10, domain: 1)")
        print("  --limit N     only test first N candidates (adhoc)")