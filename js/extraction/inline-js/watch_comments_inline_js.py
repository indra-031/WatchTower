#!/usr/bin/env python3
"""
WatchTower - Extraction : Comments (Inline JS)
Same state-machine lexer as js/comments, applied to inline-js files.

Writes: database/<program>/js/extraction/inline-js/comments.txt
"""

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
EXTRACTION_ROOT = SCRIPT_DIR.parent
if str(EXTRACTION_ROOT) not in sys.path:
    sys.path.insert(0, str(EXTRACTION_ROOT))

from _shared import (
    sanitize, find_program_by_scope, get_all_programs, now,
    _find_project_root,
)

BASE_DIR = _find_project_root(Path(__file__))
DATABASE_DIR = BASE_DIR / "database"
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
from configs.colors import colors


INPUT_SUBDIR = "inline-js"   # download/inline-js/
OUTPUT_TOOL = "inline-js"    # extraction/inline-js/


def extract_comments(js):
    comments = []
    NORMAL, LINE, BLOCK, STR_S, STR_D, TEMPL = 0, 1, 2, 3, 4, 5
    state = NORMAL
    buf = ""
    i, n = 0, len(js)
    while i < n:
        c = js[i]
        nxt = js[i + 1] if i + 1 < n else ""
        if state == NORMAL:
            if c == "/" and nxt == "/":
                state, buf = LINE, ""
                i += 1
            elif c == "/" and nxt == "*":
                state, buf = BLOCK, ""
                i += 1
            elif c == "'":
                state = STR_S
            elif c == '"':
                state = STR_D
            elif c == "`":
                state = TEMPL
        elif state == LINE:
            if c == "\n":
                if buf.strip():
                    comments.append("//" + buf.strip())
                state = NORMAL
            else:
                buf += c
        elif state == BLOCK:
            if c == "*" and nxt == "/":
                if buf.strip():
                    comments.append("/*" + buf.strip() + "*/")
                state = NORMAL
                i += 1
            else:
                buf += c
        elif state == STR_S:
            if c == "\\":
                i += 1
            elif c == "'":
                state = NORMAL
        elif state == STR_D:
            if c == "\\":
                i += 1
            elif c == '"':
                state = NORMAL
        elif state == TEMPL:
            if c == "\\":
                i += 1
            elif c == "`":
                state = NORMAL
        i += 1
    if state == LINE and buf.strip():
        comments.append("//" + buf.strip())
    return comments


def process_program(program):
    pn = program["program_name"]
    pd = program["path"]
    js_dir = pd / "js" / "download" / INPUT_SUBDIR
    if not js_dir.exists():
        print(f"{colors.YELLOW}⚠️ No {INPUT_SUBDIR} for {pn}{colors.RESET}\n")
        return 0

    out_dir = pd / "js" / "extraction" / OUTPUT_TOOL
    out_file = out_dir / "comments.txt"

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    output = []
    files = 0
    total = 0
    for js_path in sorted(js_dir.glob("*.js")):
        files += 1
        try:
            data = js_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        comments = extract_comments(data)
        if not comments:
            continue
        output.append(f"=== {js_path.name} ===")
        output.extend(comments)
        output.append("")
        total += len(comments)

    if not output:
        print(f"     {colors.YELLOW}no comments found{colors.RESET}\n")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(output), encoding="utf-8")
    print(f"     Files    : {files}")
    print(f"     Comments : {total}")
    print(f"     {colors.GREEN}💾 saved → {out_file}{colors.RESET}\n")
    return total


def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — Extract Inline JS Comments{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_comments_inline_js.py <domain>")
            print("       python3 watch_comments_inline_js.py --all")
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