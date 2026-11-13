#!/usr/bin/env python3
"""
WatchTower - Extraction : Inline JS

Extracts inline <script> blocks from downloaded HTML files, saves each
unique block as a hashed .js file for downstream secret scanners.

Writes (NOT extraction/ — goes into download/ for downstream tools):
  database/<program>/js/download/inline-js/<md5>.js
  database/<program>/js/download/hash-map/inline-js-hash-map.txt

Inputs:
  database/<program>/js/download/html/*.html

Deduplication:
  Content-based md5 hash. Same inline script in 100 pages → 1 file.
  The hash map records ``<md5> <source_filename>`` per occurrence.

Usage:
  python3 watch_inline_js.py <domain>
  python3 watch_inline_js.py --all

Requires:
  pip install beautifulsoup4
"""

import sys
import hashlib
from pathlib import Path

try:
    from bs4 import BeautifulSoup
except ImportError:
    print("❌ beautifulsoup4 not installed. Run: pip install beautifulsoup4")
    sys.exit(1)


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
    from datetime import datetime
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
            import json
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
    import json
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
            progs.append({
                "program_name": data.get("program_name", d.name),
                "path": d,
            })
        except Exception:
            continue
    return progs


def hash_content(content):
    return hashlib.md5(content.encode("utf-8", errors="ignore")).hexdigest()


def extract_from_html(html_text):
    """Return list of inline <script> blocks (strings, non-empty)."""
    soup = BeautifulSoup(html_text, "html.parser")
    blocks = []
    for script in soup.find_all("script"):
        if script.get("src"):
            continue
        code = script.string
        if not code or not code.strip():
            continue
        blocks.append(code.strip())
    return blocks


def process_program(program):
    pn = program["program_name"]
    pd = program["path"]

    html_dir = pd / "js" / "download" / "html"
    if not html_dir.exists():
        print(f"{colors.YELLOW}⚠️ No downloaded HTML for {pn}{colors.RESET}\n")
        return {"files": 0, "blocks": 0, "unique": 0}

    js_dir = pd / "js" / "download" / "inline-js"
    map_dir = pd / "js" / "download" / "hash-map"
    js_dir.mkdir(parents=True, exist_ok=True)
    map_dir.mkdir(parents=True, exist_ok=True)
    map_file = map_dir / "inline-js-hash-map.txt"

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    seen_hashes = set()
    total_blocks = 0
    html_files = 0

    # Rewrite map from scratch (idempotent)
    map_file.write_text("", encoding="utf-8")

    for html_path in sorted(html_dir.glob("*")):
        if not html_path.is_file():
            continue
        if html_path.suffix.lower() not in (".html", ".htm"):
            continue
        html_files += 1

        try:
            html = html_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        for code in extract_from_html(html):
            total_blocks += 1
            h = hash_content(code)
            js_path = js_dir / f"{h}.js"
            if h not in seen_hashes:
                seen_hashes.add(h)
                if not js_path.exists():
                    js_path.write_text(code, encoding="utf-8")
            with map_file.open("a", encoding="utf-8") as m:
                m.write(f"{h} {html_path.name}\n")

    print(f"     HTML files     : {html_files}")
    print(f"     Inline blocks  : {total_blocks}")
    print(f"     Unique files   : {len(seen_hashes)}")
    print(f"     {colors.GREEN}💾 saved → {js_dir}{colors.RESET}\n")

    return {"files": html_files, "blocks": total_blocks, "unique": len(seen_hashes)}


def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — Extract Inline JS{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_inline_js.py <domain>")
            print("       python3 watch_inline_js.py --all")
            sys.exit(1)
        domain = non_flags[0].strip().lower().lstrip("*.")
        program = find_program_by_scope(domain)
        if not program:
            print(f"{colors.RED}❌ Scope '{domain}' not found{colors.RESET}")
            sys.exit(1)
        pname = program.get("program_name", "unknown")
        programs = [{"program_name": pname, "path": DATABASE_DIR / sanitize(pname)}]

    total_unique = 0
    for prog in programs:
        s = process_program(prog)
        total_unique += s["unique"]

    print(f"{colors.GREEN}✅ Inline JS extraction complete "
          f"({total_unique} unique file(s)){colors.RESET}")


if __name__ == "__main__":
    main()