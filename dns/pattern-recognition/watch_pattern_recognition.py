#!/usr/bin/env python3
"""
WatchTower - Pattern Recognition
Extracts numeric patterns from subdomains and generates permutations
to discover more subdomains (e.g. dev1, dev2, dev3...).

Saves results to:
  database/<program>/enum-output/pattern-recognition.json
  database/<program>/enum-output/pattern_done.json

Usage:
  python3 watch_pattern_recognition.py <domain>
"""

import sys
import os
import re
import subprocess
import tempfile
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
import shutil


# =========================
# Paths
# =========================

BASE_DIR = Path(__file__).resolve().parent.parent
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
    return name.strip().lower().replace(" ", "-").replace("/", "-").replace("\\", "-").replace(":", "-")


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
    massdns_path = shutil.which("massdns")
    if massdns_path:
        return massdns_path
    for path in ["/usr/bin/massdns", "/usr/local/bin/massdns", str(Path.home() / "go/bin/massdns")]:
        if os.path.exists(path):
            return path
    return "massdns"


def find_shuffledns() -> str:
    shuffledns_path = shutil.which("shuffledns")
    if shuffledns_path:
        return shuffledns_path
    for path in ["/usr/bin/shuffledns", "/usr/local/bin/shuffledns", str(Path.home() / "go/bin/shuffledns")]:
        if os.path.exists(path):
            return path
    return "shuffledns"


def filter_subdomains(subs: list, domain: str) -> list:
    pattern = r'\.?\s*' + re.escape(domain) + r'$'
    filtered = []
    for sub in subs:
        sub = sub.strip().lower()
        if not sub or '*' in sub:
            continue
        if re.search(pattern, sub, re.IGNORECASE):
            filtered.append(sub)
    return sorted(list(set(filtered)))


def get_programs_with_subdomains() -> list:
    programs = []
    if not DATABASE_DIR.exists():
        return programs
    for prog_dir in DATABASE_DIR.iterdir():
        if not prog_dir.is_dir():
            continue
        program_file = prog_dir / "program.json"
        if not program_file.exists():
            continue
        try:
            with program_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except:
            continue
        all_file = prog_dir / "enum-output" / "all-subdomains.json"
        if not all_file.exists():
            continue
        try:
            with all_file.open("r", encoding="utf-8") as f:
                subs_data = json.load(f)
        except:
            continue
        if not subs_data:
            continue
        scopes = data.get("scope", [])
        if not scopes:
            continue
        domain = extract_domain(scopes[0])
        program_name = data.get("program_name", prog_dir.name)
        programs.append({
            "program_name": program_name,
            "domain": domain,
            "path": prog_dir,
            "subdomains": set(subs_data.keys()),
        })
    return programs


def load_all_subdomains(program_name: str) -> dict:
    safe_name = sanitize_name(program_name)
    all_file = DATABASE_DIR / safe_name / "enum-output" / "all-subdomains.json"
    if not all_file.exists():
        return {}
    try:
        with all_file.open("r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}


def save_all_subdomains(program_name: str, data: dict):
    safe_name = sanitize_name(program_name)
    all_file = DATABASE_DIR / safe_name / "enum-output" / "all-subdomains.json"
    all_file.parent.mkdir(parents=True, exist_ok=True)
    with all_file.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def save_pattern_recognition_results(program_name: str, domain: str, new_subs: list):
    if not new_subs:
        return
    safe_name = sanitize_name(program_name)
    timestamp = current_time()
    source = "pattern_recognition"
    result_file = DATABASE_DIR / safe_name / "enum-output" / "pattern-recognition.json"
    result_file.parent.mkdir(parents=True, exist_ok=True)
    if result_file.exists():
        try:
            with result_file.open("r", encoding="utf-8") as f:
                existing = json.load(f)
        except:
            existing = {"scans": []}
    else:
        existing = {"scans": []}
    existing["scans"].append({
        "timestamp": timestamp,
        "domain": domain,
        "source": source,
        "subdomains_count": len(new_subs),
        "subdomains": sorted(new_subs),
    })
    with result_file.open("w", encoding="utf-8") as f:
        json.dump(existing, f, indent=4, ensure_ascii=False)
    print(f"     {colors.GREEN}💾 pattern-recognition.json → {result_file}{colors.RESET}")


# =========================
# Pattern Done Tracking
# =========================

def load_pattern_done(program_name: str) -> set:
    safe_name = sanitize_name(program_name)
    done_file = DATABASE_DIR / safe_name / "enum-output" / "pattern_done.json"
    if not done_file.exists():
        return set()
    try:
        with done_file.open("r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return set(data)
            return set()
    except:
        return set()


def save_pattern_done(program_name: str, done_set: set):
    safe_name = sanitize_name(program_name)
    done_file = DATABASE_DIR / safe_name / "enum-output" / "pattern_done.json"
    done_file.parent.mkdir(parents=True, exist_ok=True)
    with done_file.open("w", encoding="utf-8") as f:
        json.dump(sorted(done_set), f, indent=4, ensure_ascii=False)


# =========================
# Pattern Extraction and Generation
# =========================

def extract_patterns(subdomains: set, domain: str, done_set: set) -> list:
    """
    Extract patterns from subdomains that are NOT in done_set.
    """
    patterns = []
    for sub in subdomains:
        if sub in done_set:
            continue
        if not sub.endswith(domain):
            continue
        prefix = sub[:-(len(domain) + 1)]
        if not prefix:
            continue
        for match in re.finditer(r'\d+', prefix):
            num_str = match.group(0)
            start = match.start()
            end = match.end()
            # Extract letter(s) before number
            letter_before = ''
            if start > 0 and prefix[start - 1].isalpha():
                j = start - 1
                while j >= 0 and prefix[j].isalpha():
                    j -= 1
                letter_before = prefix[j + 1:start]
            # Extract letter(s) after number
            letter_after = ''
            if end < len(prefix) and prefix[end].isalpha():
                j = end
                while j < len(prefix) and prefix[j].isalpha():
                    j += 1
                letter_after = prefix[end:j]
            # Only keep if letter_before or letter_after length is 1 or 2
            if (len(letter_before) in (1, 2)) or (len(letter_after) in (1, 2)):
                before = prefix[:start - len(letter_before)] if letter_before else prefix[:start]
                after = prefix[end + len(letter_after):] if letter_after else prefix[end:]
                patterns.append({
                    'before': before,
                    'letter_before': letter_before,
                    'num': int(num_str),
                    'letter_after': letter_after,
                    'after': after,
                    'original': sub,
                })
    return patterns


def generate_permutations(patterns: list, domain: str, max_num: int = 100) -> set:
    """
    Generate permutations:
    - Change numbers from 1 to max_num
    - Change single letters (a-z)
    - Change double letters (aa-zz) - limited to first 5 letters to reduce volume
    """
    letters = 'abcdefghijklmnopqrstuvwxyz'
    # For double letters, use first 5 letters to reduce volume (a-e)
    double_letters = [a + b for a in letters[:5] for b in letters[:5]]  # aa-ee
    perms = set()
    for pat in patterns:
        before = pat['before']
        lb = pat['letter_before']
        num = pat['num']
        la = pat['letter_after']
        after = pat['after']
        # Number variations
        for n in range(1, max_num + 1):
            if n == num:
                continue
            new_prefix = before + lb + str(n) + la + after
            perms.add(f"{new_prefix}.{domain}")
        # Single letter variations (if letter_before exists)
        if lb and len(lb) == 1:
            for l in letters:
                if l == lb:
                    continue
                for n in range(1, max_num + 1):
                    if n == num:
                        continue
                    new_prefix = before + l + str(n) + la + after
                    perms.add(f"{new_prefix}.{domain}")
        # Double letter variations (if letter_before exists and length is 2)
        if lb and len(lb) == 2:
            for dl in double_letters:
                if dl == lb:
                    continue
                for n in range(1, max_num + 1):
                    if n == num:
                        continue
                    new_prefix = before + dl + str(n) + la + after
                    perms.add(f"{new_prefix}.{domain}")
        # Single letter variations (if letter_after exists)
        if la and len(la) == 1:
            for l in letters:
                if l == la:
                    continue
                for n in range(1, max_num + 1):
                    if n == num:
                        continue
                    new_prefix = before + lb + str(n) + l + after
                    perms.add(f"{new_prefix}.{domain}")
        # Double letter variations (if letter_after exists and length is 2)
        if la and len(la) == 2:
            for dl in double_letters:
                if dl == la:
                    continue
                for n in range(1, max_num + 1):
                    if n == num:
                        continue
                    new_prefix = before + lb + str(n) + dl + after
                    perms.add(f"{new_prefix}.{domain}")
        # Also add original for testing
        perms.add(pat['original'])
    return perms


# =========================
# Chunk resolution with shuffledns
# =========================

def resolve_chunk(chunk: list, domain: str, resolvers: str, massdns_bin: str, chunk_id: int, total_chunks: int) -> set:
    if not chunk:
        return set()
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tmp:
        chunk_file = tmp.name
        for item in chunk:
            tmp.write(item + "\n")
    shuffledns_bin = find_shuffledns()
    cmd = (
        f"{shuffledns_bin} -l {chunk_file} -d {domain} -r {resolvers} -m {massdns_bin} "
        f"-mode resolve -t 30 -retries 3 -silent"
    )
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
        if result.returncode != 0:
            print(f"     {colors.YELLOW}   Chunk {chunk_id} error (return code {result.returncode}){colors.RESET}")
        stdout_lines = result.stdout.strip().splitlines()
    except subprocess.TimeoutExpired:
        print(f"     {colors.YELLOW}   Chunk {chunk_id} timeout{colors.RESET}")
        return set()
    except Exception as e:
        print(f"     {colors.RED}   Chunk {chunk_id} error: {e}{colors.RESET}")
        return set()
    finally:
        try:
            os.unlink(chunk_file)
        except:
            pass
    found = set()
    for line in stdout_lines:
        line = line.strip()
        if line and line.endswith(domain):
            found.add(line)
    return found


def resolve_sequential(permutations: list, domain: str, resolvers: str, massdns_bin: str, chunk_size: int = 10000) -> set:
    total = len(permutations)
    if total == 0:
        return set()
    chunks = []
    for i in range(0, total, chunk_size):
        chunks.append(permutations[i:i + chunk_size])
    num_chunks = len(chunks)
    print(f"     {colors.CYAN}🔍 Resolving {total:,} permutations in {num_chunks} chunks (size {chunk_size:,})...{colors.RESET}")
    all_found = set()
    for idx, chunk in enumerate(chunks):
        chunk_num = idx + 1
        print(f"     {colors.GRAY}→ Chunk {chunk_num}/{num_chunks} ({len(chunk)} hosts){colors.RESET}")
        found = resolve_chunk(chunk, domain, resolvers, massdns_bin, chunk_num, num_chunks)
        all_found.update(found)
        print(f"        found {len(found)} live, total so far: {len(all_found)}")
    print(f"     {colors.CYAN}📋 All chunks processed, total live found: {len(all_found)}{colors.RESET}")
    return all_found


# =========================
# Update functions
# =========================

def update_all_subdomains(program_name: str, domain: str, new_live: set, source: str = "pattern_recognition"):
    if not new_live:
        return
    timestamp = current_time()
    data = load_all_subdomains(program_name)
    added = 0
    for sub in new_live:
        if sub not in data:
            data[sub] = {
                "first_seen": timestamp,
                "last_seen": timestamp,
                "sources": {
                    source: {
                        "first_seen": timestamp,
                        "last_seen": timestamp,
                        "domain": domain,
                    }
                },
            }
            added += 1
        else:
            data[sub]["last_seen"] = timestamp
            if source not in data[sub].get("sources", {}):
                data[sub].setdefault("sources", {})[source] = {
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "domain": domain,
                }
            else:
                data[sub]["sources"][source]["last_seen"] = timestamp
            if "sources" not in data[sub]:
                data[sub]["sources"] = {}
    if added:
        save_all_subdomains(program_name, data)
        print(f"     {colors.GREEN}✅ Added {added} new subdomains to all-subdomains.json{colors.RESET}")
    else:
        print(f"     {colors.YELLOW}⚠️ No new subdomains to add to all-subdomains.json{colors.RESET}")


def update_dns_lives(program_name: str, domain: str, new_live: set):
    if not new_live:
        return
    safe_name = sanitize_name(program_name)
    timestamp = current_time()
    dns_file = DATABASE_DIR / safe_name / "dns" / "lives.json"
    dns_file.parent.mkdir(parents=True, exist_ok=True)
    if dns_file.exists():
        try:
            with dns_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except:
            data = {}
    else:
        data = {}
    added = 0
    for sub in new_live:
        if sub not in data:
            data[sub] = {
                "domain": domain,
                "ips": [],
                "cname": [],
                "last_seen": timestamp,
            }
            added += 1
        else:
            data[sub]["last_seen"] = timestamp
    with dns_file.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    if added:
        print(f"     {colors.GREEN}✅ Added {added} new subdomains to dns/lives.json{colors.RESET}")
    else:
        print(f"     {colors.YELLOW}⚠️ No new subdomains to add to dns/lives.json{colors.RESET}")
    print(f"     {colors.CYAN}📋 dns/lives.json now has {len(data)} total entries{colors.RESET}")


# =========================
# Main for one program
# =========================

def main_for_program(program_info: dict):
    program_name = program_info["program_name"]
    domain = program_info["domain"]
    all_subs = program_info["subdomains"]

    resolvers = get_resolvers_file()
    massdns_bin = find_massdns()

    # Load done set
    done_set = load_pattern_done(program_name)
    print(f"     {colors.CYAN}📋 Already done (pattern applied): {len(done_set)} subdomains{colors.RESET}")

    # Filter out done subdomains from all_subs for pattern extraction
    remaining_subs = all_subs - done_set
    print(f"     {colors.CYAN}📋 Remaining subdomains to process: {len(remaining_subs)}{colors.RESET}")

    patterns = extract_patterns(remaining_subs, domain, done_set)
    print(f"     {colors.CYAN}📋 Extracted {len(patterns)} patterns from remaining subdomains{colors.RESET}")

    if not patterns:
        print(f"     {colors.YELLOW}⚠️ No new patterns found (all subdomains already processed or no number patterns).{colors.RESET}")
        return []

    perms = generate_permutations(patterns, domain, max_num=100)
    print(f"     {colors.CYAN}📋 Generated {len(perms)} permutations (numbers 1-100 + letter variations){colors.RESET}")

    sample_perms = list(perms)[:5]
    if sample_perms:
        print(f"     {colors.GRAY}      Sample permutations:{colors.RESET}")
        for p in sample_perms:
            print(f"     {colors.GRAY}        {p}{colors.RESET}")

    print(f"     {colors.CYAN}📋 Total to resolve (including original): {len(perms)}{colors.RESET}")

    sorted_perms = sorted(list(perms))
    live_set = resolve_sequential(sorted_perms, domain, resolvers, massdns_bin, chunk_size=10000)

    valid_live = filter_subdomains(list(live_set), domain)
    new_live = set(valid_live) - all_subs
    print(f"     {colors.CYAN}📋 New live subdomains discovered: {len(new_live)}{colors.RESET}")

    # Mark processed originals as done
    processed_originals = {p['original'] for p in patterns}
    done_set.update(processed_originals)
    save_pattern_done(program_name, done_set)
    print(f"     {colors.CYAN}📋 Updated done list: {len(done_set)} subdomains{colors.RESET}")

    if new_live:
        update_all_subdomains(program_name, domain, new_live, source="pattern_recognition")
        update_dns_lives(program_name, domain, new_live)
        save_pattern_recognition_results(program_name, domain, new_live)
    else:
        print(f"     {colors.YELLOW}⚠️ No new live subdomains found{colors.RESET}")

    return list(new_live)


# =========================
# Main
# =========================

if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ["-h", "--help"]:
        print("Usage: python3 watch_pattern_recognition.py <domain>")
        print("Example: python3 watch_pattern_recognition.py example.com")
        print("")
        print("Note: Use watch_pattern_recognition_all.py to run on all programs.")
        sys.exit(1)

    domain = extract_domain(sys.argv[1])
    programs = get_programs_with_subdomains()
    target = None
    for p in programs:
        if p["domain"] == domain:
            target = p
            break
    if not target:
        print(f"{colors.RED}❌ No program found with domain {domain} or no subdomains.{colors.RESET}")
        sys.exit(1)
    print(f"{colors.CYAN}[{current_time()}] Pattern Recognition for {domain}{colors.RESET}")
    new_live = main_for_program(target)
    if new_live:
        print(f"{colors.GREEN}✅ Found {len(new_live)} new live subdomains{colors.RESET}")
        for h in sorted(new_live):
            print(f"   {h}")
    else:
        print(f"{colors.YELLOW}⚠️ No new live subdomains found{colors.RESET}")