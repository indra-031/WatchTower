#!/usr/bin/env python3
"""
WatchTower - Parameter Wordlist Enhancer

Appends discovered parameter names to a shared wordlist that downstream
parameter-discovery tools (arjun, x8, paramspider) can use.

Inputs (per program):
  database/<program>/js/extraction/merge/parameters-merge.txt

Output (global, shared across all programs):
  wordlist/parameter/wordlist-parameter.txt

Incremental — only new parameters are appended.

Usage:
  python3 watch_parameter_wordlist.py <domain>
  python3 watch_parameter_wordlist.py --all
"""

import sys
import json
from pathlib import Path
from datetime import datetime


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
    return start.resolve().parent.parent


BASE_DIR = _find_project_root(Path(__file__))
DATABASE_DIR = BASE_DIR / "database"
WORDLIST_FILE = BASE_DIR / "wordlist" / "parameter" / "wordlist-parameter.txt"

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
from configs.colors import colors


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize(name):
    return (name.strip().lower()
            .replace(" ", "-").replace("/", "-")
            .replace("\\", "-").replace(":", "-"))


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
        scopes = data.get("scope", []) + data.get("out_of_scope", data.get("ooscope", []))
        for s in scopes:
            clean = s.lstrip("*.").lower()
            if scope_name == clean or scope_name.endswith("." + clean):
                return data
    return None


def get_all_programs():
    if not DATABASE_DIR.exists():
        return []
    out = []
    for d in DATABASE_DIR.iterdir():
        if not d.is_dir() or d.name.startswith("_"):
            continue
        if not (d / "program.json").exists():
            continue
        try:
            data = json.loads((d / "program.json").read_text())
            scopes = [s.strip() for s in data.get("scope", []) if s and s.strip()]
            if not scopes:
                continue
            out.append({"program_name": data.get("program_name", d.name), "path": d})
        except Exception:
            continue
    return out


def read_wordlist():
    if not WORDLIST_FILE.exists():
        return set()
    try:
        return {line.strip() for line in WORDLIST_FILE.read_text(errors="ignore").splitlines()
                if line.strip()}
    except Exception:
        return set()


def write_wordlist(words):
    WORDLIST_FILE.parent.mkdir(parents=True, exist_ok=True)
    sorted_words = sorted(words)
    WORDLIST_FILE.write_text(
        "\n".join(sorted_words) + ("\n" if sorted_words else ""),
        encoding="utf-8",
    )


def read_program_params(pd):
    f = pd / "js" / "extraction" / "merge" / "parameters-merge.txt"
    if not f.exists():
        return set()
    try:
        return {line.strip() for line in f.read_text(errors="ignore").splitlines()
                if line.strip()}
    except Exception:
        return set()


def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — Parameter Wordlist{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_parameter_wordlist.py <domain>")
            print("       python3 watch_parameter_wordlist.py --all")
            sys.exit(1)
        domain = non_flags[0].strip().lower().lstrip("*.")
        program = find_program_by_scope(domain)
        if not program:
            print(f"{colors.RED}❌ Scope '{domain}' not found{colors.RESET}")
            sys.exit(1)
        pname = program.get("program_name", "unknown")
        programs = [{"program_name": pname, "path": DATABASE_DIR / sanitize(pname)}]

    # Collect new params from all programs
    total_new = 0
    for prog in programs:
        pn = prog["program_name"]
        pd = prog["path"]
        new_params = read_program_params(pd)
        if not new_params:
            print(f"     {colors.YELLOW}⚠️ {pn}: no parameters-merge.txt{colors.RESET}")
            continue

        existing = read_wordlist()
        to_add = new_params - existing
        if to_add:
            write_wordlist(existing | to_add)
            total_new += len(to_add)
            print(f"     {colors.GREEN}{pn}: +{len(to_add)} new "
                  f"({len(new_params)} found, {len(existing)} already in wordlist)"
                  f"{colors.RESET}")
        else:
            print(f"     {colors.GRAY}{pn}: 0 new ({len(new_params)} found, all cached)"
                  f"{colors.RESET}")

    final = read_wordlist()
    print()
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ Parameter wordlist updated{colors.RESET}")
    print(f"{colors.GREEN}   New added  : +{total_new}{colors.RESET}")
    print(f"{colors.GREEN}   Total words: {len(final)}{colors.RESET}")
    print(f"{colors.GREEN}   Wordlist   : {WORDLIST_FILE}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")


if __name__ == "__main__":
    main()