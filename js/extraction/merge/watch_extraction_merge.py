#!/usr/bin/env python3
"""
WatchTower - Extraction : Merge

Aggregates all extraction outputs across subdirectories per program.
Groups by filename: e.g., all ``comments.txt`` from extraction/{html,js,
inline-js}/ → ``comments-merge.txt``. JSON files (libraries.json) are
merged as lists with per-item dedup.

Skips the ``merge`` subdirectory itself (to avoid self-recursion).

Writes:
  database/<program>/js/extraction/merge/<name>-merge.txt
  database/<program>/js/extraction/merge/<name>-merge.json

Usage:
  python3 watch_extraction_merge.py <domain>
  python3 watch_extraction_merge.py --all
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


def collect_files(extraction_dir):
    """All .txt/.json files under extraction/, excluding merge/ itself."""
    files = []
    for f in extraction_dir.rglob("*"):
        if not f.is_file():
            continue
        if f.suffix.lower() not in (".txt", ".json"):
            continue
        if "merge" in f.parts:
            continue
        files.append(f)
    return files


def merge_txt(files, out_file):
    seen = set()
    for f in files:
        try:
            for line in f.read_text(errors="ignore").splitlines():
                line = line.strip()
                if line:
                    seen.add(line)
        except Exception:
            continue
    sorted_lines = sorted(seen)
    out_file.write_text("\n".join(sorted_lines) + ("\n" if sorted_lines else ""),
                         encoding="utf-8")
    return len(sorted_lines)


def merge_json(files, out_file):
    seen = set()
    merged = []
    for f in files:
        try:
            data = json.loads(f.read_text())
        except Exception:
            continue
        items = data if isinstance(data, list) else [data]
        for item in items:
            key = json.dumps(item, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            merged.append(item)
    out_file.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    return len(merged)


def process_program(program):
    pn = program["program_name"]
    pd = program["path"]
    extraction_dir = pd / "js" / "extraction"
    if not extraction_dir.exists():
        print(f"{colors.YELLOW}⚠️ No extraction dir for {pn}{colors.RESET}\n")
        return 0

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    files = collect_files(extraction_dir)
    if not files:
        print(f"     {colors.YELLOW}no extraction files{colors.RESET}\n")
        return 0

    # Group by filename
    grouped = {}
    for f in files:
        grouped.setdefault(f.name, []).append(f)

    merge_dir = extraction_dir / "merge"
    merge_dir.mkdir(parents=True, exist_ok=True)

    total_items = 0
    for name, file_list in sorted(grouped.items()):
        base, ext = name.rsplit(".", 1) if "." in name else (name, "")
        out_name = f"{base}-merge.{ext}"
        out_file = merge_dir / out_name

        if ext == "txt":
            count = merge_txt(file_list, out_file)
        elif ext == "json":
            count = merge_json(file_list, out_file)
        else:
            continue

        if count:
            print(f"     {out_name:<30} {count:>6} items  "
                  f"{colors.GRAY}({len(file_list)} source(s)){colors.RESET}")
            total_items += count

    print(f"\n     {colors.GREEN}💾 saved → {merge_dir}{colors.RESET}\n")
    return total_items


def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — Extraction Merge{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_extraction_merge.py <domain>")
            print("       python3 watch_extraction_merge.py --all")
            sys.exit(1)
        domain = non_flags[0].strip().lower().lstrip("*.")
        program = find_program_by_scope(domain)
        if not program:
            print(f"{colors.RED}❌ Scope '{domain}' not found{colors.RESET}")
            sys.exit(1)
        pname = program.get("program_name", "unknown")
        programs = [{"program_name": pname, "path": DATABASE_DIR / sanitize(pname)}]

    total = 0
    for prog in programs:
        total += process_program(prog)
    print(f"{colors.GREEN}✅ Merge complete ({total} items){colors.RESET}")


if __name__ == "__main__":
    main()