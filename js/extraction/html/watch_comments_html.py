#!/usr/bin/env python3
"""
WatchTower - Extraction : HTML Comments

Extracts <!-- ... --> comments from downloaded HTML files.
Grouped per source file for context.

Writes:
  database/<program>/js/extraction/html/comments.txt

Inputs:
  database/<program>/js/download/html/*.html

Usage:
  python3 watch_comments_html.py <domain>
  python3 watch_comments_html.py --all
"""

import sys
import re
from pathlib import Path


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
from configs.colors import colors as _c  # noqa
from datetime import datetime


COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)


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
    progs = []
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
            progs.append({"program_name": data.get("program_name", d.name), "path": d})
        except Exception:
            continue
    return progs


def process_program(program):
    pn = program["program_name"]
    pd = program["path"]

    html_dir = pd / "js" / "download" / "html"
    if not html_dir.exists():
        print(f"{colors.YELLOW}⚠️ No downloaded HTML for {pn}{colors.RESET}\n")
        return 0

    out_dir = pd / "js" / "extraction" / "html"
    out_file = out_dir / "comments.txt"

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    output_lines = []
    file_count = 0
    total_comments = 0

    for html_path in sorted(html_dir.glob("*")):
        if not html_path.is_file():
            continue
        if html_path.suffix.lower() not in (".html", ".htm"):
            continue
        file_count += 1

        try:
            data = html_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        comments = [
            "<!--" + c.strip() + "-->"
            for c in COMMENT_RE.findall(data)
            if c.strip()
        ]
        if not comments:
            continue

        output_lines.append(f"=== {html_path.name} ===")
        output_lines.extend(comments)
        output_lines.append("")
        total_comments += len(comments)

    if not output_lines:
        print(f"     {colors.YELLOW}no comments found{colors.RESET}\n")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(output_lines), encoding="utf-8")

    print(f"     Files    : {file_count}")
    print(f"     Comments : {total_comments}")
    print(f"     {colors.GREEN}💾 saved → {out_file}{colors.RESET}\n")
    return total_comments


def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — Extract HTML Comments{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_comments_html.py <domain>")
            print("       python3 watch_comments_html.py --all")
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
    print(f"{colors.GREEN}✅ Complete ({total} comments){colors.RESET}")


if __name__ == "__main__":
    main()