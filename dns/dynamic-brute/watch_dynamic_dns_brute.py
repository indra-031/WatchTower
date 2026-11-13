#!/usr/bin/env python3
"""
WatchTower - Dynamic DNS Brute-force (dnsgen + shuffledns)

Generates permutations of known subdomains with dnsgen, then resolves
them via shuffledns (which handles wildcard filtering).

Reads:  database/<program>/dns/lives.json  ->  known subdomains
Writes: database/<program>/dns/nsbrute.json
        database/<program>/dns/lives.json
        database/<program>/enum-output/all-subdomains.json

Source label: "ns_brute_dynamic"

Usage:
  python3 watch_dynamic_ns_brute.py <domain>
"""

import sys
import os
import re
import time
import signal
import shutil
import subprocess
import tempfile
import json
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
# Tuning constants
# =========================

DNSGEN_TIMEOUT = 120           # seconds for dnsgen to generate permutations
SHUFFLEDNS_THREADS = 100
MIN_RESOLVE_TIMEOUT = 300
MAX_RESOLVE_TIMEOUT = 1800
SECONDS_PER_100_PERMS = 6      # rough estimate
PROGRESS_INTERVAL = 10


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
        return str(brute_resolvers)
    local = DNS_DIR / "resolvers.txt"
    if local.exists():
        return str(local)
    home = Path.home() / ".resolvers.txt"
    if home.exists():
        return str(home)
    return "8.8.8.8,1.1.1.1"


def find_massdns() -> str:
    try:
        result = subprocess.run(["which", "massdns"], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except Exception:
        pass
    for path in ["/usr/bin/massdns", "/usr/local/bin/massdns",
                 str(Path.home() / "go/bin/massdns")]:
        if os.path.exists(path):
            return path
    return "massdns"


def find_dnsgen() -> str:
    """Locate dnsgen in PATH or common install dirs."""
    binary = shutil.which("dnsgen")
    if binary:
        return binary
    for path in [
        str(Path.home() / ".local" / "bin" / "dnsgen"),
        "/usr/local/bin/dnsgen",
        "/usr/bin/dnsgen",
    ]:
        if os.path.exists(path):
            return path
    return ""


def load_wildcard_status(program_name: str, domain: str):
    """Returns True/False/None based on wildcard-test.json for this domain."""
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


def get_existing_subdomains(program_name: str, domain: str) -> set:
    """Load known subdomains for a domain from dns/lives.json."""
    safe_name = sanitize_name(program_name)
    existing = set()
    dns_lives = DATABASE_DIR / safe_name / "dns" / "lives.json"
    if dns_lives.exists():
        try:
            data = json.loads(dns_lives.read_text())
            for sub in data.keys():
                if sub == domain or sub.endswith("." + domain):
                    existing.add(sub)
        except Exception:
            pass
    return existing


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


# =========================
# dnsgen step
# =========================

def generate_permutations(known_subs: set, domain: str) -> list:
    """
    Run dnsgen on the known subdomains, return new candidate hostnames
    (deduplicated, filtered to the target domain, excluding originals).
    """
    dnsgen_bin = find_dnsgen()
    if not dnsgen_bin:
        print(f"     {colors.RED}❌ dnsgen not found. Install: pip install dnsgen{colors.RESET}")
        return []

    # Write known subs to a temp file (dnsgen accepts file or stdin)
    in_fd, in_path = tempfile.mkstemp(prefix="wt_dnsgen_in_", suffix=".txt")
    out_fd, out_path = tempfile.mkstemp(prefix="wt_dnsgen_out_", suffix=".txt")
    os.close(in_fd)
    os.close(out_fd)
    in_file = Path(in_path)
    out_file = Path(out_path)

    try:
        in_file.write_text("\n".join(sorted(known_subs)) + "\n", encoding="utf-8")

        cmd = [
            "nice", "-n", "19",
            "ionice", "-c", "3",
            dnsgen_bin,
            str(in_file),
        ]

        print(f"     {colors.CYAN}🧬 Generating permutations with dnsgen "
              f"({len(known_subs)} known subs)...{colors.RESET}")

        with open(out_file, "w", encoding="utf-8") as out_fp:
            try:
                p = subprocess.Popen(
                    cmd,
                    stdout=out_fp,
                    stderr=subprocess.PIPE,
                    text=True,
                    preexec_fn=os.setsid,
                )
            except FileNotFoundError:
                print(f"     {colors.RED}❌ dnsgen not found{colors.RESET}")
                return []
            except Exception as e:
                print(f"     {colors.RED}❌ Failed to start dnsgen: {e}{colors.RESET}")
                return []

            start = time.time()
            while p.poll() is None:
                if time.time() - start > DNSGEN_TIMEOUT:
                    try:
                        pgid = os.getpgid(p.pid)
                        os.killpg(pgid, signal.SIGTERM)
                        time.sleep(2)
                        if p.poll() is None:
                            os.killpg(pgid, signal.SIGKILL)
                    except Exception:
                        pass
                    print(f"     {colors.YELLOW}⚠️ dnsgen timeout after {DNSGEN_TIMEOUT}s{colors.RESET}")
                    break
                time.sleep(0.5)

            try:
                stderr_out = p.stderr.read() if p.stderr else ""
            except Exception:
                stderr_out = ""

        # Parse output
        perms = []
        if out_file.exists():
            with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    host = line.strip().lower()
                    if not host:
                        continue
                    perms.append(host)

        # Deduplicate + filter to target domain + remove originals
        perms = filter_subdomains(perms, domain)
        new_perms = [p for p in perms if p not in known_subs]

        print(f"     {colors.GREEN}✅ dnsgen: {len(new_perms)} new candidate(s) "
              f"(from {len(perms)} total generated){colors.RESET}")

        if stderr_out and "error" in stderr_out.lower():
            first_err = stderr_out.strip().splitlines()[0][:150]
            print(f"     {colors.GRAY}dnsgen stderr: {first_err}{colors.RESET}")

        return new_perms

    except KeyboardInterrupt:
        print(f"\n     {colors.YELLOW}⚠️ Interrupted during dnsgen{colors.RESET}")
        return []
    finally:
        for path in (in_file, out_file):
            try:
                path.unlink()
            except Exception:
                pass


# =========================
# Resolution step
# =========================

def resolve_candidates(candidates: list, domain: str) -> list:
    """Resolve candidates with shuffledns (wildcard-filtered)."""
    if not candidates:
        return []

    resolvers = get_resolvers_file()
    massdns_bin = find_massdns()
    shuffledns_bin = shutil.which("shuffledns") or "shuffledns"

    estimated = max(MIN_RESOLVE_TIMEOUT, (len(candidates) * SECONDS_PER_100_PERMS) // 100)
    timeout = min(MAX_RESOLVE_TIMEOUT, estimated)

    q_fd, q_path = tempfile.mkstemp(prefix="wt_dyn_q_", suffix=".txt")
    o_fd, o_path = tempfile.mkstemp(prefix="wt_dyn_o_", suffix=".txt")
    os.close(q_fd)
    os.close(o_fd)
    queries_file = Path(q_path)
    out_file = Path(o_path)

    try:
        with open(queries_file, "w", encoding="utf-8") as f:
            for sub in candidates:
                f.write(sub + "\n")

        cmd = [
            "nice", "-n", "19",
            "ionice", "-c", "3",
            shuffledns_bin,
            "-l", str(queries_file),
            "-d", domain,
            "-r", resolvers,
            "-m", massdns_bin,
            "-mode", "resolve",
            "-t", str(SHUFFLEDNS_THREADS),
            "-silent",
        ]

        print(f"     {colors.CYAN}🔍 Resolving {len(candidates)} candidates "
              f"(threads={SHUFFLEDNS_THREADS}, timeout={timeout}s)...{colors.RESET}")

        with open(out_file, "w", encoding="utf-8") as out_fp:
            try:
                p = subprocess.Popen(
                    cmd,
                    stdout=out_fp,
                    stderr=subprocess.DEVNULL,
                    preexec_fn=os.setsid,
                )
            except FileNotFoundError:
                print(f"     {colors.RED}❌ shuffledns not found{colors.RESET}")
                return []
            except Exception as e:
                print(f"     {colors.RED}❌ Failed to start shuffledns: {e}{colors.RESET}")
                return []

            start = time.time()
            last_tick = 0
            while p.poll() is None:
                elapsed = time.time() - start
                if elapsed > timeout:
                    try:
                        pgid = os.getpgid(p.pid)
                        os.killpg(pgid, signal.SIGTERM)
                        time.sleep(3)
                        if p.poll() is None:
                            os.killpg(pgid, signal.SIGKILL)
                    except Exception:
                        pass
                    print(f"     {colors.YELLOW}⚠️ Resolve timeout after {timeout}s{colors.RESET}")
                    break
                if elapsed - last_tick >= PROGRESS_INTERVAL:
                    last_tick = elapsed
                    try:
                        size = out_file.stat().st_size
                    except Exception:
                        size = 0
                    print(f"     {colors.GRAY}   {int(elapsed)}s elapsed, output {size} bytes{colors.RESET}")
                time.sleep(1)

        # Parse
        found = set()
        if out_file.exists():
            with open(out_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    host = line.strip().lower()
                    if host and (host == domain or host.endswith("." + domain)):
                        found.add(host)

        print(f"     {colors.GREEN}✅ Resolved {len(found)} live host(s) "
              f"out of {len(candidates)}{colors.RESET}")

        return list(found)

    except KeyboardInterrupt:
        print(f"\n     {colors.YELLOW}⚠️ Interrupted during resolution — partial results kept{colors.RESET}")
        return []
    finally:
        for path in (queries_file, out_file):
            try:
                path.unlink()
            except Exception:
                pass


# =========================
# Core
# =========================

def dynamic_brute(domain: str, program_name: str) -> list:
    """
    Full dynamic brute-force pipeline:
      1. Load known subdomains from lives.json
      2. Generate permutations with dnsgen
      3. Resolve permutations with shuffledns
      4. Return only newly discovered hosts
    """
    print(f"\n{colors.MAGENTA}{'─'*60}{colors.RESET}")
    print(f"{colors.MAGENTA}🧬 Dynamic Brute-force (dnsgen) — {domain}{colors.RESET}")
    print(f"{colors.MAGENTA}{'─'*60}{colors.RESET}")

    # Wildcard warning
    wc = load_wildcard_status(program_name, domain)
    if wc is True:
        print(f"     {colors.YELLOW}⚠️ This domain has wildcard DNS. "
              f"shuffledns will filter wildcards, but review results carefully.{colors.RESET}")

    known = get_existing_subdomains(program_name, domain)
    print(f"     {colors.CYAN}📋 Known subdomains: {len(known)}{colors.RESET}")

    if not known:
        print(f"     {colors.YELLOW}⚠️ No known subdomains — run static brute or enum first.{colors.RESET}")
        return []

    # Step 1: generate permutations
    perms = generate_permutations(known, domain)
    if not perms:
        print(f"     {colors.YELLOW}⚠️ dnsgen produced no new candidates.{colors.RESET}")
        return []

    # Step 2: resolve
    live = resolve_candidates(perms, domain)
    if not live:
        print(f"     {colors.YELLOW}⚠️ No live hosts from permutations.{colors.RESET}")
        return []

    # Step 3: only new (not already in lives)
    new_live = [h for h in live if h not in known]
    print(f"     {colors.CYAN}📋 New live subdomains: {len(new_live)}{colors.RESET}")

    return new_live


# =========================
# Save results
# =========================

def save_results(program_name: str, domain: str, subdomains: list):
    if not subdomains:
        print(f"     {colors.YELLOW}⚠️ No new subdomains to save for {domain}{colors.RESET}")
        return

    safe_name = sanitize_name(program_name)
    timestamp = current_time()
    source = "ns_brute_dynamic"

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
        print("Usage: python3 watch_dynamic_ns_brute.py <domain>")
        print("Example: python3 watch_dynamic_ns_brute.py example.com")
        print("")
        print("Note: use watch_dynamic_ns_brute_all.py to run on all scopes.")
        sys.exit(1)

    raw_input = sys.argv[1]
    domain = extract_domain(raw_input)
    if raw_input != domain:
        print(f"{colors.GRAY}Input: {raw_input}{colors.RESET}")
        print(f"{colors.GRAY}Domain: {domain}{colors.RESET}")

    program = find_program_by_scope(domain)
    if not program:
        print(f"{colors.RED}[{current_time()}] scope '{domain}' does not exist{colors.RESET}")
        sys.exit(1)

    program_name = program.get("program_name", "unknown")
    print(f"{colors.CYAN}[{current_time()}] Dynamic Brute-force for '{domain}'{colors.RESET}")
    print(f"{colors.CYAN}📦 Program: {program_name}{colors.RESET}")

    new_live = dynamic_brute(domain, program_name)

    if new_live:
        save_results(program_name, domain, new_live)
        print(f"\n{colors.GREEN}{'='*50}{colors.RESET}")
        print(f"{colors.GREEN}✅ Dynamic brute complete{colors.RESET}")
        print(f"{colors.GREEN}   Domain: {domain}{colors.RESET}")
        print(f"{colors.GREEN}   New:    {len(new_live)} subdomains{colors.RESET}")
        print(f"{colors.GREEN}{'='*50}{colors.RESET}")
    else:
        print(f"{colors.YELLOW}⚠️ No new subdomains discovered.{colors.RESET}")