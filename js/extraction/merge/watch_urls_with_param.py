#!/usr/bin/env python3
"""
WatchTower - Extraction : URLs With Parameters

Collects URLs from all merge outputs (discovery + extraction + xnlinkfinder
+ paths) and filters to in-scope URLs that contain a query string (``?``).

Uses WatchTower's scope helper — ``out_of_scope`` wins over ``scope``.

Writes:
  database/<program>/js/extraction/merge/urls-with-param.txt

Usage:
  python3 watch_urls_with_param.py <domain>
  python3 watch_urls_with_param.py --all
"""

import sys
from pathlib import Path
from urllib.parse import urlparse
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
from configs.scope import load_scope_from_path, is_in_scope


INPUT_FILES = [
    # discovery merge
    ("js/discovery/merge", "urls.txt"),
    # extraction merge
    ("js/extraction/merge", "urls-merge.txt"),
    ("js/extraction/merge", "links-merge.txt"),
    ("js/extraction/merge", "paths-merge.txt"),
]


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize(name):
    return (name.strip().lower()
            .replace(" ", "-").replace("/", "-")
            .replace("\\", "-").replace(":", "-"))


def find_program_by_scope(scope_name):
    import json
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
    import json
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


def url_hostname(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def process_program(program):
    pn = program["program_name"]
    pd = program["path"]

    out_file = pd / "js" / "extraction" / "merge" / "urls-with-param.txt"
    out_file.parent.mkdir(parents=True, exist_ok=True)

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    scope, oos = load_scope_from_path(pd / "program.json")

    all_urls = set()
    source_counts = {}
    for rel_dir, filename in INPUT_FILES:
        f = pd / rel_dir / filename
        if not f.exists():
            continue
        try:
            lines = f.read_text(errors="ignore").splitlines()
        except Exception:
            continue
        added = 0
        for line in lines:
            url = line.strip()
            if url:
                all_urls.add(url)
                added += 1
        if added:
            source_counts[filename] = added

    print(f"     Sources: {sum(source_counts.values())} URLs")
    for name, count in source_counts.items():
        print(f"       {colors.GRAY}• {name}: {count}{colors.RESET}")

    in_scope_with_param = set()
    oos_skipped = 0
    for url in all_urls:
        if "?" not in url:
            continue
        h = url_hostname(url)
        if not h:
            continue
        if (scope or oos) and not is_in_scope(h, scope, oos):
            oos_skipped += 1
            continue
        in_scope_with_param.add(url)

    if not in_scope_with_param:
        print(f"     {colors.YELLOW}no in-scope URLs with params{colors.RESET}\n")
        out_file.write_text("", encoding="utf-8")
        return 0

    sorted_urls = sorted(in_scope_with_param)
    out_file.write_text("\n".join(sorted_urls) + "\n", encoding="utf-8")

    if oos_skipped:
        print(f"     {colors.GRAY}⏭  {oos_skipped} URL(s) skipped (out of scope){colors.RESET}")
    print(f"     {colors.GREEN}✅ {len(sorted_urls)} URLs with params{colors.RESET}")
    print(f"     {colors.GREEN}💾 saved → {out_file}{colors.RESET}\n")
    return len(sorted_urls)


def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — URLs With Parameters{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_urls_with_param.py <domain>")
            print("       python3 watch_urls_with_param.py --all")
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
    print(f"{colors.GREEN}✅ Complete ({total} URLs){colors.RESET}")


if __name__ == "__main__":
    main()