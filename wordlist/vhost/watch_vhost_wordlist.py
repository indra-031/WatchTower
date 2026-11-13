#!/usr/bin/env python3
"""
WatchTower - VHost Wordlist Enhancer (single program)

Extracts word combinations from known subdomains and appends them
to the shared vhost wordlist:

  wordlist/vhost/custom-vhost.txt

Same generation rules as the subdomain enhancer (see
watch_subdomain_wordlist.py for details).

Usage:
  python3 watch_vhost_wordlist.py <domain>
"""

import sys
import re
import json
from itertools import permutations
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
    return start.resolve().parent


BASE_DIR = _find_project_root(Path(__file__))
DATABASE_DIR = BASE_DIR / "database"

# VHost wordlist output.
VHOST_WORDLIST = BASE_DIR / "wordlist" / "vhost" / "custom-vhost.txt"


# =========================
# Imports from configs/
# =========================

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from configs.colors import colors


# =========================
# Configuration
# =========================

MAX_FULL_PERMUTATION_LABELS = 4


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
        # Prefer new key; fall back to legacy "ooscope".
        scopes = (
            data.get("scope", [])
            + data.get("out_of_scope", data.get("ooscope", []))
        )
        for scope in scopes:
            clean_scope = scope.lstrip("*.").lower()
            if scope_name == clean_scope or scope_name.endswith("." + clean_scope):
                return data
    return None


# =========================
# Combination generation
# =========================

def generate_combinations(labels: list, max_full_perm: int = MAX_FULL_PERMUTATION_LABELS) -> set:
    """
    Same logic as watch_subdomain_wordlist.generate_combinations().
    See that module for the full explanation.
    """
    results = set()
    n = len(labels)

    if n == 0:
        return results

    for label in labels:
        results.add(label)

    if n >= 2:
        for perm in permutations(labels, 2):
            results.add(".".join(perm))

    if n <= max_full_perm:
        for r in range(3, n + 1):
            for perm in permutations(labels, r):
                results.add(".".join(perm))
    else:
        results.add(".".join(labels))

    return results


def extract_words_from_subdomain(subdomain: str, base_domains: list) -> set:
    subdomain = subdomain.strip().lower()
    if not subdomain:
        return set()

    matched = None
    for bd in base_domains:
        bd = bd.strip().lower().lstrip("*.")
        if not bd:
            continue
        if subdomain == bd or subdomain.endswith("." + bd):
            if matched is None or len(bd) > len(matched):
                matched = bd

    if matched:
        if subdomain == matched:
            return set()
        prefix = subdomain[:-(len(matched) + 1)]
    else:
        parts = subdomain.split(".")
        if len(parts) <= 2:
            return set()
        prefix = ".".join(parts[:-2])

    if not prefix:
        return set()

    labels = [p for p in prefix.split(".") if p]
    if not labels:
        return set()

    return generate_combinations(labels)


def filter_words(words: set) -> set:
    valid = set()
    label_re = re.compile(r'^[a-z0-9][a-z0-9_-]*$')
    for w in words:
        w = w.strip().lower()
        if not w:
            continue
        if len(w) < 2 or len(w) > 253:
            continue
        if "." in w:
            parts = w.split(".")
            if all(label_re.match(p) for p in parts if p):
                valid.add(w)
        else:
            if label_re.match(w):
                valid.add(w)
    return valid


def collect_words_from_program(program_name: str, base_domains: list):
    safe = sanitize_name(program_name)
    all_subs_file = DATABASE_DIR / safe / "enum-output" / "all-subdomains.json"

    if not all_subs_file.exists():
        return set(), 0

    try:
        data = json.loads(all_subs_file.read_text(encoding="utf-8"))
    except Exception:
        return set(), 0

    words = set()
    for subdomain in data.keys():
        words.update(extract_words_from_subdomain(subdomain, base_domains))

    return words, len(data)


# =========================
# Wordlist I/O
# =========================

def load_words(path: Path) -> set:
    if not path.exists():
        return set()
    try:
        return {
            line.strip().lower()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        }
    except Exception:
        return set()


def save_words(path: Path, words: set):
    path.parent.mkdir(parents=True, exist_ok=True)
    content = "\n".join(sorted(words)) + ("\n" if words else "")
    path.write_text(content, encoding="utf-8")


def merge_into(path: Path, new_words: set) -> dict:
    existing = load_words(path)
    new_added = new_words - existing
    merged = existing | new_words
    save_words(path, merged)
    return {
        "existing": len(existing),
        "new_added": len(new_added),
        "total": len(merged),
    }


# =========================
# Core
# =========================

def enhance_wordlist(program_name: str, scopes: list) -> dict:
    base_domains = [s.strip().lstrip("*.").lower() for s in scopes if s and s.strip()]

    words, sub_count = collect_words_from_program(program_name, base_domains)
    filtered = filter_words(words)

    if not filtered:
        return {
            "subdomains": sub_count,
            "extracted": 0,
            "stats": {"existing": 0, "new_added": 0, "total": 0},
        }

    stats = merge_into(VHOST_WORDLIST, filtered)

    return {
        "subdomains": sub_count,
        "extracted": len(filtered),
        "stats": stats,
    }


# =========================
# Main
# =========================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 watch_vhost_wordlist.py <domain>")
        print("Example: python3 watch_vhost_wordlist.py example.com")
        print("")
        print("Note: use watch_vhost_wordlist_all.py to run on all programs.")
        sys.exit(1)

    domain = extract_domain(sys.argv[1])

    program = find_program_by_scope(domain)
    if not program:
        print(f"{colors.RED}[{current_time()}] scope '{domain}' does not exist{colors.RESET}")
        sys.exit(1)

    program_name = program.get("program_name", "unknown")
    scopes = program.get("scope", [])
    base_domains = [s.strip().lstrip("*.").lower() for s in scopes if s and s.strip()]

    print(f"{colors.CYAN}[{current_time()}] VHost Wordlist Enhancer — {program_name}{colors.RESET}")
    print(f"{colors.CYAN}📦 Program : {program_name}{colors.RESET}")
    print(f"{colors.CYAN}🌐 Scopes  : {', '.join(base_domains) if base_domains else '(none)'}{colors.RESET}")
    print()

    result = enhance_wordlist(program_name, scopes)

    if result["subdomains"] == 0:
        print(f"{colors.YELLOW}⚠️ No all-subdomains.json for {program_name}{colors.RESET}")
        sys.exit(0)

    print(f"{colors.CYAN}📋 Subdomains : {result['subdomains']}{colors.RESET}")
    print(f"{colors.CYAN}🔎 Words      : {result['extracted']} (after filter){colors.RESET}")
    print()

    st = result["stats"]
    print(f"{colors.GREEN}📁 wordlist/vhost/custom-vhost.txt{colors.RESET}")
    print(f"   {colors.GRAY}🆕 +{st['new_added']} new{colors.RESET}  "
          f"{colors.CYAN}📋 total: {st['total']}{colors.RESET}  "
          f"{colors.GRAY}(was {st['existing']}){colors.RESET}")

    print()
    print(f"{colors.GREEN}✅ Complete{colors.RESET}")