#!/usr/bin/env python3
"""
WatchTower - Program Sync
Reads JSON files from a directory and saves each as a program
in the file-based database (database/<program-name>/program.json).

Sanitization:
  List fields (scope, out_of_scope, cidr, asn, ip) are cleaned on write —
  empty strings, whitespace-only entries, and non-string values are dropped.
  This converts common manual-edit leftovers like ``[""]`` into ``[]``.
"""

from pathlib import Path
import json
import argparse
import sys


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
# Helpers
# =========================

def sanitize_name(name: str) -> str:
    """
    Convert program name into safe directory name.
    """
    return (
        name.strip()
        .lower()
        .replace(" ", "-")
        .replace("/", "-")
        .replace("\\", "-")
        .replace(":", "-")
    )


def clean_list(items) -> list:
    """
    Return a cleaned list of non-empty strings.

    Handles the common cases:
      - ``[""]``         → ``[]``
      - ``["", ""]``     → ``[]``
      - ``["  "]``       → ``[]``
      - ``["a", "", "b"]`` → ``["a", "b"]``
      - non-list input   → ``[]``
      - ``None``         → ``[]``

    Numeric / boolean entries are converted to strings, then validated.
    """
    if not isinstance(items, list):
        return []

    cleaned = []
    for item in items:
        if item is None:
            continue
        s = str(item).strip()
        if s:
            cleaned.append(s)
    return cleaned


def ensure_database_dir():
    """
    Create database directory if not exists.
    """
    DATABASE_DIR.mkdir(parents=True, exist_ok=True)


def save_program(program_name: str, data: dict):
    """
    Save program data into:
    database/<program-name>/program.json
    """
    safe_name = sanitize_name(program_name)

    program_dir = DATABASE_DIR / safe_name
    program_dir.mkdir(parents=True, exist_ok=True)

    output_file = program_dir / "program.json"

    with output_file.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

    print(f"{colors.GREEN}💾 Saved -> {output_file}{colors.RESET}")


# =========================
# Core
# =========================

def process_file(path: Path):
    """
    Process single JSON file.
    """
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)

    except json.JSONDecodeError as e:
        print(f"{colors.RED}❌ JSON decode error in {path}: {e}{colors.RESET}")
        return

    except Exception as e:
        print(f"{colors.RED}❌ Error reading {path}: {e}{colors.RESET}")
        return

    if not isinstance(data, dict):
        print(f"{colors.YELLOW}⚠️ Skipping non-dict JSON: {path}{colors.RESET}")
        return

    if not data:
        print(f"{colors.YELLOW}⚠️ Empty JSON file: {path}{colors.RESET}")
        return

    program_name = data.get("program_name")

    if not program_name:
        print(f"{colors.YELLOW}⚠️ Missing program_name in: {path}{colors.RESET}")
        return

    # Prefer new keys; fall back to legacy aliases.
    # Every list field is passed through clean_list so ["", ...] becomes [].
    raw_scope = data.get("scope", data.get("scopes", []))
    raw_oos = data.get(
        "out_of_scope",
        data.get("ooscope", data.get("ooscopes", [])),
    )
    raw_cidr = data.get("cidr", data.get("cidrs", []))
    raw_asn = data.get("asn", data.get("asns", []))
    raw_ip = data.get("ip", data.get("ips", []))

    cleaned_scope = clean_list(raw_scope)
    cleaned_oos = clean_list(raw_oos)
    cleaned_cidr = clean_list(raw_cidr)
    cleaned_asn = clean_list(raw_asn)
    cleaned_ip = clean_list(raw_ip)

    # Report dirty inputs so the user knows their file had junk
    for label, raw, cleaned in (
        ("scope", raw_scope, cleaned_scope),
        ("out_of_scope", raw_oos, cleaned_oos),
        ("cidr", raw_cidr, cleaned_cidr),
        ("asn", raw_asn, cleaned_asn),
        ("ip", raw_ip, cleaned_ip),
    ):
        if isinstance(raw, list) and len(raw) != len(cleaned):
            dropped = len(raw) - len(cleaned)
            print(
                f"{colors.YELLOW}   ⚠️  {program_name}: cleaned {label} "
                f"({dropped} empty entr{'y' if dropped == 1 else 'ies'} removed)"
                f"{colors.RESET}"
            )

    output_data = {
        "program_name": program_name,
        "scope": cleaned_scope,
        "out_of_scope": cleaned_oos,
        "cidr": cleaned_cidr,
        "asn": cleaned_asn,
        "ip": cleaned_ip,
    }

    save_program(program_name, output_data)


def scan_directory(directory: Path):
    """
    Scan for JSON files in the given directory only (non-recursive).
    Subdirectories are ignored.
    """
    if not directory.exists():
        print(f"{colors.RED}❌ Directory not found: {directory}{colors.RESET}")
        return

    files = sorted(directory.glob("*.json"))

    if not files:
        print(f"{colors.YELLOW}⚠️ No JSON files found in: {directory}{colors.RESET}")
        return

    print(f"{colors.CYAN}🔍 Found {len(files)} JSON files{colors.RESET}")

    for file_path in files:
        process_file(file_path)


# =========================
# Main
# =========================

def main():
    parser = argparse.ArgumentParser(
        description="WatchTower Program Sync - File-based, no database"
    )

    parser.add_argument(
        "directory",
        nargs="?",
        default=".",
        help="Directory containing JSON files (default: current directory)"
    )

    args = parser.parse_args()

    ensure_database_dir()

    scan_directory(Path(args.directory).resolve())


if __name__ == "__main__":
    main()