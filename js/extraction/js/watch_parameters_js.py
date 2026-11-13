#!/usr/bin/env python3
"""
WatchTower - Extraction : Parameters (JS + inline HTML)
Advanced local parameter discovery across JS files AND inline <script>
blocks in downloaded HTML. Combines URL params, object literals, and
location.search/hash usage.

Writes: database/<program>/js/extraction/js/parameters.txt
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


URL_PARAM_RE = re.compile(r"[?&]([a-zA-Z0-9_%\-]{2,})=")
BODY_PARAM_RE = re.compile(r"([a-zA-Z0-9_%-]{2,})\s*=")
OBJECT_RE = re.compile(r"{([^}]{1,300})}")
LOCATION_RE = re.compile(r"location\.(search|hash)")
INLINE_SCRIPT_RE = re.compile(r"<script[^>]*>(.*?)</script>", re.I | re.S)

IGNORE_PARAMS = {
    "var", "let", "const", "if", "for", "while",
    "true", "false", "null", "undefined", "return",
    "function", "this", "new", "typeof",
}


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


def clean_param(p):
    p = p.strip()
    if len(p) < 2:
        return None
    if p.lower() in IGNORE_PARAMS:
        return None
    if p.isdigit():
        return None
    return p


def extract_from_text(text, params):
    for p in URL_PARAM_RE.findall(text):
        cp = clean_param(p)
        if cp:
            params.add(cp)
    for block in OBJECT_RE.findall(text):
        for p in BODY_PARAM_RE.findall(block):
            cp = clean_param(p)
            if cp:
                params.add(cp)
    if LOCATION_RE.search(text):
        params.add("location_search")
        params.add("location_hash")


def process_program(program):
    pn = program["program_name"]
    pd = program["path"]
    js_dir = pd / "js" / "download" / "js"
    html_dir = pd / "js" / "download" / "html"

    if not js_dir.exists() and not html_dir.exists():
        print(f"{colors.YELLOW}⚠️ No downloaded assets for {pn}{colors.RESET}\n")
        return 0

    out_dir = pd / "js" / "extraction" / "js"
    out_file = out_dir / "parameters.txt"

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    params = set()
    js_files = html_files = 0

    if js_dir.exists():
        for js_path in sorted(js_dir.glob("*.js")):
            js_files += 1
            try:
                extract_from_text(js_path.read_text(encoding="utf-8", errors="ignore"), params)
            except Exception:
                continue

    if html_dir.exists():
        for html_path in sorted(html_dir.glob("*")):
            if html_path.suffix.lower() not in (".html", ".htm"):
                continue
            html_files += 1
            try:
                html = html_path.read_text(encoding="utf-8", errors="ignore")
                for script in INLINE_SCRIPT_RE.findall(html):
                    extract_from_text(script, params)
            except Exception:
                continue

    if not params:
        print(f"     {colors.YELLOW}no parameters found{colors.RESET}\n")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(sorted(params)) + "\n", encoding="utf-8")

    print(f"     JS files   : {js_files}")
    print(f"     HTML files : {html_files}")
    print(f"     Parameters : {len(params)}")
    print(f"     {colors.GREEN}💾 saved → {out_file}{colors.RESET}\n")
    return len(params)


def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — Extract JS Parameters{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_parameters_js.py <domain>")
            print("       python3 watch_parameters_js.py --all")
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
    print(f"{colors.GREEN}✅ Complete ({total} parameters){colors.RESET}")


if __name__ == "__main__":
    main()