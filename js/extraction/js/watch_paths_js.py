#!/usr/bin/env python3
"""
WatchTower - Extraction : Paths (JS)
Extracts URL paths from JS source code (excludes regex literals,
comments, www.*, *.com and single-word fragments).

Writes: database/<program>/js/extraction/js/paths.txt
"""

import sys
import re
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


PATH_RE = re.compile(
    r"""
    (?<![\w$])
    (
        /[a-zA-Z0-9][a-zA-Z0-9\-._~/%?=&+#:@]*
    )
    """,
    re.VERBOSE,
)


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


def looks_like_real_path(p):
    return ("/" in p[1:] or "." in p or "?" in p or "=" in p or any(c.isdigit() for c in p))


def is_valid_path(p):
    if not p.startswith("/"):
        return False
    if p.startswith(("/^", "/(", "/[", "//")):
        return False
    if not looks_like_real_path(p):
        return False
    if p.startswith("/www."):
        return False
    if re.match(r"^/[^/]+\.com(/|$)", p):
        return False
    if len(p) < 3:
        return False
    return True


def process_program(program):
    pn = program["program_name"]
    pd = program["path"]
    js_dir = pd / "js" / "download" / "js"

    if not js_dir.exists():
        print(f"{colors.YELLOW}⚠️ No downloaded JS for {pn}{colors.RESET}\n")
        return 0

    out_dir = pd / "js" / "extraction" / "js"
    out_file = out_dir / "paths.txt"

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    paths = set()
    files = 0

    for js_path in sorted(js_dir.glob("*.js")):
        files += 1
        try:
            data = js_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for p in PATH_RE.findall(data):
            if is_valid_path(p):
                paths.add(p)

    if not paths:
        print(f"     {colors.YELLOW}no paths found{colors.RESET}\n")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(sorted(paths)) + "\n", encoding="utf-8")

    print(f"     Files : {files}")
    print(f"     Paths : {len(paths)}")
    print(f"     {colors.GREEN}💾 saved → {out_file}{colors.RESET}\n")
    return len(paths)


def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — Extract JS Paths{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_paths_js.py <domain>")
            print("       python3 watch_paths_js.py --all")
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
    print(f"{colors.GREEN}✅ Complete ({total} paths){colors.RESET}")


if __name__ == "__main__":
    main()