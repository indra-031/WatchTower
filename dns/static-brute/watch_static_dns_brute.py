#!/usr/bin/env python3
"""
WatchTower - DNS Static Brute-force (shuffledns)

Uses shuffledns in bruteforce mode — no manual massdns batching needed.
shuffledns handles wildcard filtering, concurrency, and deduplication.

- Persistent merged wordlist cache
- nice/ionice + process-group kill on timeout
- Per-program done-file (database/<program>/dns/static_brute_done.json)
- Strict wildcard checking enabled

Usage:
  python3 watch_static_ns_brute.py <domain>
  python3 watch_static_ns_brute.py <domain> --force
"""

import sys
import os
import re
import json
import time
import signal
import shutil
import subprocess
import tempfile
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


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
    return start.resolve()


BASE_DIR = _find_project_root(Path(__file__))
DATABASE_DIR = BASE_DIR / "database"
DNS_DIR = BASE_DIR / "dns"
BRUTE_DIR = DNS_DIR / "brute-files"


# =========================
# Imports from configs/
# =========================

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from configs.colors import colors


# =========================
# Tuning
# =========================

SHUFFLEDNS_THREADS = 1000          # -t : concurrent massdns resolves
SHUFFLEDNS_RETRIES = 3             # -retries
SHUFFLEDNS_WILDCARD_THREADS = 25   # -wt : concurrent wildcard checks
RUN_TIMEOUT = 3600                 # overall cap per domain (seconds)

SORT_MEMORY_LIMIT = "50M"

SOURCE_WORDLISTS = [
    "best-dns-wordlist.txt",
    "2m-subdomains.txt",
    "4_lower.txt",
    "altdns-words.txt",
    "dnsgen-words.txt",
]

MERGED_CACHE = BRUTE_DIR / ".merged-words.txt"


# =========================
# Basic helpers
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
            clean_scope = scope.lstrip("*.").lower()
            if scope_name == clean_scope or scope_name.endswith("." + clean_scope):
                return data
    return None


def get_resolvers_file() -> str:
    brute_resolvers = BRUTE_DIR / "resolvers.txt"
    if brute_resolvers.exists():
        with open(brute_resolvers) as f:
            lines = [l.strip() for l in f if l.strip()]
        if len(lines) < 10:
            print(f"     {colors.YELLOW}⚠️ Only {len(lines)} resolvers found{colors.RESET}")
        return str(brute_resolvers)
    print(f"     {colors.YELLOW}⚠️ resolvers.txt not found, using 8.8.8.8,1.1.1.1{colors.RESET}")
    return "8.8.8.8,1.1.1.1"


def find_massdns() -> str:
    """shuffledns needs massdns binary in PATH or common locations."""
    binary = shutil.which("massdns")
    if binary:
        return binary
    for path in ["/usr/bin/massdns", "/usr/local/bin/massdns",
                 str(Path.home() / "go/bin/massdns")]:
        if os.path.exists(path):
            return path
    return "massdns"


def find_shuffledns() -> str:
    binary = shutil.which("shuffledns")
    if binary:
        return binary
    for path in [str(Path.home() / "go/bin/shuffledns"),
                 "/usr/local/bin/shuffledns",
                 "/usr/bin/shuffledns"]:
        if os.path.exists(path):
            return path
    return "shuffledns"


def filter_subdomains(subs, domain):
    pattern = r'\.?\s*' + re.escape(domain) + r'$'
    filtered = []
    for sub in subs:
        sub = sub.strip().lower()
        if not sub or '*' in sub:
            continue
        if re.search(pattern, sub, re.IGNORECASE):
            filtered.append(sub)
    return sorted(set(filtered))


def load_wildcard_status(program_name, domain):
    safe = sanitize_name(program_name)
    wc_file = DATABASE_DIR / safe / "dns" / "wildcard-test.json"
    if not wc_file.exists():
        return None
    try:
        data = json.loads(wc_file.read_text())
    except Exception:
        return None
    for scan in reversed(data.get("scans", [])):
        if scan.get("domain") == domain:
            return bool(scan.get("wildcard_detected"))
    return None


# =========================
# Per-program done-file
# =========================

def get_done_file(program_name: str) -> Path:
    safe = sanitize_name(program_name)
    return DATABASE_DIR / safe / "dns" / "static_brute_done.json"


def load_done(program_name: str) -> dict:
    f = get_done_file(program_name)
    if not f.exists():
        return {}
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_done(program_name: str, done: dict):
    f = get_done_file(program_name)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(done, indent=4, ensure_ascii=False), encoding="utf-8")


def mark_done(program_name: str, domain: str):
    done = load_done(program_name)
    done[domain] = current_time()
    save_done(program_name, done)


# =========================
# Merged wordlist cache
# =========================

def get_or_build_merged_wordlist():
    if not BRUTE_DIR.exists():
        print(f"     {colors.RED}❌ Brute-files directory not found: {BRUTE_DIR}{colors.RESET}")
        return None

    sources = []
    for name in SOURCE_WORDLISTS:
        p = BRUTE_DIR / name
        if p.exists():
            sources.append(p)
        else:
            print(f"     {colors.YELLOW}⚠️ {name} not found, skipping{colors.RESET}")

    if not sources:
        print(f"     {colors.RED}❌ No wordlists found in {BRUTE_DIR}{colors.RESET}")
        return None

    if MERGED_CACHE.exists():
        cache_mtime = MERGED_CACHE.stat().st_mtime
        if all(p.stat().st_mtime <= cache_mtime for p in sources):
            size_mb = MERGED_CACHE.stat().st_size / (1024 * 1024)
            print(f"     {colors.GRAY}♻️  Using cached merged wordlist ({size_mb:.1f} MB){colors.RESET}")
            return MERGED_CACHE

    print(f"     {colors.CYAN}📋 Building merged wordlist cache...{colors.RESET}")
    tmp_cache = MERGED_CACHE.with_suffix(".tmp")
    tmp_dir = tempfile.gettempdir()

    try:
        tmp_cache.unlink()
    except Exception:
        pass

    files_arg = " ".join(f"'{p}'" for p in sources)
    cmd = (
        f"cat {files_arg} 2>/dev/null | "
        f"LC_ALL=C sort -u --parallel=1 -S {SORT_MEMORY_LIMIT} -T {tmp_dir} "
        f"> '{tmp_cache}'"
    )

    try:
        result = subprocess.run(
            ["bash", "-c", cmd],
            capture_output=True, text=True, timeout=900,
        )
        if result.returncode != 0:
            err = (result.stderr or "").strip()
            if err:
                print(f"     {colors.YELLOW}{err[:200]}{colors.RESET}")
            print(f"     {colors.RED}❌ Failed to build merged wordlist{colors.RESET}")
            return None
    except subprocess.TimeoutExpired:
        print(f"     {colors.RED}❌ Merge timeout after 900s{colors.RESET}")
        return None

    if not tmp_cache.exists() or tmp_cache.stat().st_size == 0:
        print(f"     {colors.RED}❌ Merged wordlist is empty{colors.RESET}")
        return None

    tmp_cache.rename(MERGED_CACHE)

    try:
        wc = subprocess.run(["wc", "-l", str(MERGED_CACHE)],
                            capture_output=True, text=True, timeout=30)
        count = wc.stdout.strip().split()[0]
        print(f"     {colors.GREEN}✅ Merged wordlist: {count} unique words{colors.RESET}")
    except Exception:
        pass

    return MERGED_CACHE


# =========================
# Core: shuffledns bruteforce
# =========================

def ns_brute_static(domain, program_name, force=False):
    print(f"\n{colors.MAGENTA}{'─'*60}{colors.RESET}")
    print(f"{colors.MAGENTA}🔨 Static Brute-force (shuffledns) — {domain}{colors.RESET}")
    print(f"{colors.MAGENTA}{'─'*60}{colors.RESET}")

    # Done check
    done = load_done(program_name)
    if domain in done and not force:
        print(f"     {colors.GREEN}✅ Already done at {done[domain]} — skipping{colors.RESET}")
        print(f"     {colors.GRAY}   Use --force to re-run anyway.{colors.RESET}")
        return None

    # Wildcard hint
    wc = load_wildcard_status(program_name, domain)
    if wc is True:
        print(f"     {colors.YELLOW}⚠️ Wildcard DNS detected — strict-wildcard will filter false positives{colors.RESET}")

    resolvers = get_resolvers_file()
    massdns_bin = find_massdns()
    shuffledns_bin = find_shuffledns()

    wordlist = get_or_build_merged_wordlist()
    if not wordlist:
        return []

    # Output file (temp)
    fd, out_path = tempfile.mkstemp(prefix="wt_shuf_out_", suffix=".txt")
    os.close(fd)
    out_file = Path(out_path)

    cmd = [
        "nice", "-n", "19",
        "ionice", "-c", "3",
        shuffledns_bin,
        "-d", domain,
        "-w", str(wordlist),
        "-r", resolvers,
        "-mode", "bruteforce",
        "-m", massdns_bin,
        "-t", str(SHUFFLEDNS_THREADS),
        "-retries", str(SHUFFLEDNS_RETRIES),
        "-wt", str(SHUFFLEDNS_WILDCARD_THREADS),
        "-strict-wildcard",
        "-silent",
        "-o", str(out_file),
    ]

    print(f"     {colors.CYAN}📋 shuffledns bruteforce: threads={SHUFFLEDNS_THREADS}, "
          f"retries={SHUFFLEDNS_RETRIES}, wildcard-checks={SHUFFLEDNS_WILDCARD_THREADS}{colors.RESET}")
    print()

    start = time.time()
    timed_out = False

    try:
        p = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
        )
    except FileNotFoundError:
        print(f"     {colors.RED}❌ shuffledns not found{colors.RESET}")
        try:
            out_file.unlink()
        except Exception:
            pass
        return []
    except Exception as e:
        print(f"     {colors.RED}❌ Failed to start shuffledns: {e}{colors.RESET}")
        try:
            out_file.unlink()
        except Exception:
            pass
        return []

    last_tick = 0
    while p.poll() is None:
        elapsed = time.time() - start
        if elapsed > RUN_TIMEOUT:
            timed_out = True
            break
        if elapsed - last_tick >= 20:
            last_tick = elapsed
            try:
                found_so_far = sum(1 for _ in open(out_file, encoding="utf-8", errors="ignore")) if out_file.exists() else 0
            except Exception:
                found_so_far = 0
            print(f"     {colors.GRAY}   {int(elapsed)}s elapsed, {found_so_far} line(s) in output{colors.RESET}")
        time.sleep(1)

    if timed_out:
        try:
            pgid = os.getpgid(p.pid)
            os.killpg(pgid, signal.SIGTERM)
            time.sleep(3)
            if p.poll() is None:
                os.killpg(pgid, signal.SIGKILL)
        except Exception:
            pass
        print(f"     {colors.YELLOW}⚠️ shuffledns timeout after {RUN_TIMEOUT}s{colors.RESET}")

    rc = p.returncode
    stderr_tail = ""
    try:
        if p.stderr:
            raw = p.stderr.read().decode("utf-8", errors="ignore")
            stderr_tail = "\n".join(raw.strip().splitlines()[-5:])
    except Exception:
        pass

    if rc not in (0, None) and not timed_out:
        print(f"     {colors.RED}❌ shuffledns exited with code {rc}{colors.RESET}")
        if stderr_tail:
            for line in stderr_tail.splitlines():
                print(f"        {colors.YELLOW}{line[:150]}{colors.RESET}")

    # Parse output
    found = set()
    if out_file.exists():
        with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                host = line.strip().lower()
                if host and (host == domain or host.endswith("." + domain)):
                    found.add(host)

    try:
        out_file.unlink()
    except Exception:
        pass

    valid = filter_subdomains(list(found), domain)
    print()
    print(f"     {colors.GREEN}✅ shuffledns found {len(valid)} subdomains{colors.RESET}")

    # Mark done if process finished without fatal error
    if rc == 0 or timed_out:
        mark_done(program_name, domain)
        print(f"     {colors.GRAY}📝 Marked '{domain}' as done in {get_done_file(program_name)}{colors.RESET}")

    return valid


# =========================
# Save results
# =========================

def save_results(program_name, domain, subdomains):
    safe_name = sanitize_name(program_name)
    timestamp = current_time()
    source = "ns_brute_static"

    if not subdomains:
        print(f"     {colors.YELLOW}⚠️ No subdomains to save for {domain}{colors.RESET}")
        return

    dns_dir = DATABASE_DIR / safe_name / "dns"
    dns_dir.mkdir(parents=True, exist_ok=True)

    # 1. dns/nsbrute.json — scan log
    nsbrute_file = dns_dir / "nsbrute.json"
    existing = {"scans": []}
    if nsbrute_file.exists():
        try:
            existing = json.loads(nsbrute_file.read_text())
        except Exception:
            pass
    existing["scans"].append({
        "timestamp": timestamp,
        "domain": domain,
        "program_name": program_name,
        "source": source,
        "subdomains_count": len(subdomains),
        "subdomains": sorted(subdomains),
    })
    nsbrute_file.write_text(json.dumps(existing, indent=4, ensure_ascii=False))
    print(f"     {colors.GREEN}💾 nsbrute.json → {nsbrute_file}{colors.RESET}")

    # 2. dns/lives.json — master
    lives_file = dns_dir / "lives.json"
    lives = {}
    if lives_file.exists():
        try:
            lives = json.loads(lives_file.read_text())
        except Exception:
            pass

    new_count = 0
    for sub in subdomains:
        if sub not in lives:
            lives[sub] = {
                "domain": domain,
                "ips": [],
                "cname": "",
                "first_seen": timestamp,
                "last_seen": timestamp,
                "sources": [source],
            }
            new_count += 1
        else:
            lives[sub]["last_seen"] = timestamp
            if "first_seen" not in lives[sub]:
                lives[sub]["first_seen"] = timestamp
            if "sources" not in lives[sub]:
                lives[sub]["sources"] = []
            if source not in lives[sub]["sources"]:
                lives[sub]["sources"].append(source)

    lives_file.write_text(json.dumps(lives, indent=4, ensure_ascii=False))
    if new_count:
        print(f"     {colors.GREEN}🆕 {new_count} new to dns/lives.json{colors.RESET}")
    print(f"     {colors.CYAN}📋 dns/lives.json: {len(lives)} total{colors.RESET}")

    # 3. enum-output/all-subdomains.json
    enum_dir = DATABASE_DIR / safe_name / "enum-output"
    enum_dir.mkdir(parents=True, exist_ok=True)
    all_subs_file = enum_dir / "all-subdomains.json"
    all_subs = {}
    if all_subs_file.exists():
        try:
            raw = json.loads(all_subs_file.read_text())
            if isinstance(raw, dict):
                all_subs = raw
        except Exception:
            pass

    new_all = 0
    for sub in subdomains:
        if sub not in all_subs:
            all_subs[sub] = {"first_seen": timestamp, "last_seen": timestamp, "sources": {}}
            new_all += 1
        else:
            all_subs[sub]["last_seen"] = timestamp
        all_subs[sub]["sources"][source] = {
            "first_seen": all_subs[sub]["sources"].get(source, {}).get("first_seen", timestamp),
            "last_seen": timestamp,
            "domain": domain,
        }

    all_subs_file.write_text(json.dumps(dict(sorted(all_subs.items())), indent=4, ensure_ascii=False))
    if new_all:
        print(f"     {colors.GREEN}🆕 {new_all} new to all-subdomains.json{colors.RESET}")
    print(f"     {colors.CYAN}📋 all-subdomains.json: {len(all_subs)} total{colors.RESET}")


# =========================
# Main
# =========================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 watch_static_ns_brute.py <domain> [--force]")
        print("")
        print("Requires: shuffledns + massdns in PATH")
        print("Note: use watch_static_ns_brute_all.py to run on all scopes.")
        sys.exit(1)

    raw_input = sys.argv[1]
    force = "--force" in sys.argv

    domain = extract_domain(raw_input)
    if raw_input != domain:
        print(f"{colors.GRAY}Input: {raw_input}{colors.RESET}")
        print(f"{colors.GRAY}Domain: {domain}{colors.RESET}")

    program = find_program_by_scope(domain)
    if not program:
        print(f"{colors.RED}[{current_time()}] scope '{domain}' does not exist{colors.RESET}")
        sys.exit(1)

    program_name = program.get("program_name", "unknown")
    print(f"{colors.CYAN}[{current_time()}] Static Brute-force for '{domain}'{colors.RESET}")
    print(f"{colors.CYAN}📦 Program: {program_name}{colors.RESET}")

    subs = ns_brute_static(domain, program_name, force=force)

    if subs is None:
        sys.exit(0)

    if subs:
        save_results(program_name, domain, subs)
        print(f"\n{colors.GREEN}{'='*50}{colors.RESET}")
        print(f"{colors.GREEN}✅ Static Brute-force completed{colors.RESET}")
        print(f"{colors.GREEN}   Domain: {domain}{colors.RESET}")
        print(f"{colors.GREEN}   Found:  {len(subs)} subdomains{colors.RESET}")
        print(f"{colors.GREEN}{'='*50}{colors.RESET}")
    else:
        print(f"{colors.YELLOW}⚠️ No subdomains found{colors.RESET}")