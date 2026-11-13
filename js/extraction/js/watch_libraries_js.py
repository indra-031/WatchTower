#!/usr/bin/env python3
"""
WatchTower - Extraction : Libraries (JS)
Detects common JS library name+version pairs in downloaded JS files.
Same 8 patterns as HTML extractor + dedup per (lib, version, file).

Writes: database/<program>/js/extraction/js/libraries.json
  Format: [{library, version, file}, ...]
"""

import sys
import re
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


LIB_PATTERNS = [
    r"(jquery)[^\n]{0,80}?(\d+\.\d+(?:\.\d+)?)",
    r"(react)[^\n]{0,80}?(\d+\.\d+(?:\.\d+)?)",
    r"(vue)[^\n]{0,80}?(\d+\.\d+(?:\.\d+)?)",
    r"(angular)[^\n]{0,80}?(\d+\.\d+(?:\.\d+)?)",
    r"(axios)[^\n]{0,80}?(\d+\.\d+(?:\.\d+)?)",
    r"(lodash)[^\n]{0,80}?(\d+\.\d+(?:\.\d+)?)",
    r"(moment)[^\n]{0,80}?(\d+\.\d+(?:\.\d+)?)",
    r"(bootstrap)[^\n]{0,80}?(\d+\.\d+(?:\.\d+)?)",
]
LIB_REGEX = [re.compile(p, re.IGNORECASE) for p in LIB_PATTERNS]


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


def process_program(program):
    pn = program["program_name"]
    pd = program["path"]
    js_dir = pd / "js" / "download" / "js"

    if not js_dir.exists():
        print(f"{colors.YELLOW}⚠️ No downloaded JS for {pn}{colors.RESET}\n")
        return 0

    out_dir = pd / "js" / "extraction" / "js"
    out_file = out_dir / "libraries.json"

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    seen = set()
    results = []
    files = 0

    for js_path in sorted(js_dir.glob("*.js")):
        files += 1
        try:
            data = js_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for rgx in LIB_REGEX:
            for m in rgx.finditer(data):
                lib = m.group(1).lower()
                ver = m.group(2)
                key = (lib, ver, js_path.name)
                if key in seen:
                    continue
                seen.add(key)
                results.append({
                    "library": lib,
                    "version": ver,
                    "file": js_path.name,
                })

    if not results:
        print(f"     {colors.YELLOW}no libraries found{colors.RESET}\n")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print(f"     Files : {files}")
    print(f"     Hits  : {len(results)}")
    print(f"     {colors.GREEN}💾 saved → {out_file}{colors.RESET}\n")
    return len(results)


def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — Extract JS Libraries{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_libraries_js.py <domain>")
            print("       python3 watch_libraries_js.py --all")
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
    print(f"{colors.GREEN}✅ Complete ({total} library hits){colors.RESET}")


if __name__ == "__main__":
    main()