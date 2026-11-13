#!/usr/bin/env python3
"""
WatchTower - Nuclei URL Maker
Extracts HTTP URLs from each program's http/lives-http.json
and writes them to database/<program>/attack/nuclei/nuclei-urls.txt

Scope enforcement:
  - out_of_scope (and legacy "ooscope") is applied when reading URLs.
  - OOS wins over scope.
  - Redirect-source hosts are skipped (canonical host scanned once).

Usage:
  python3 nuclei_url_maker.py <domain>
  python3 nuclei_url_maker.py --all
"""

import sys
import json
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

ATTACK_SUBDIR = "attack"
NUCLEI_SUBDIR = "nuclei"


def nuclei_output_dir(program_dir: Path) -> Path:
    return program_dir / ATTACK_SUBDIR / NUCLEI_SUBDIR


if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from configs.colors import colors
from configs.scope import load_scope_from_path, is_in_scope
from configs.hosts import build_redirect_map, is_canonical


def sanitize_name(name):
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
        scopes = (
            data.get("scope", [])
            + data.get("out_of_scope", data.get("ooscope", []))
        )
        for s in scopes:
            clean = s.lstrip("*.").lower()
            if scope_name == clean or scope_name.endswith("." + clean):
                return data
    return None


def get_all_programs():
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
            progs.append({
                "program_name": data.get("program_name", d.name),
                "scopes": scopes,
                "path": d,
            })
        except Exception:
            continue
    return progs


def extract_urls(program_dir, domain, scope=None, oos=None):
    scope = scope or []
    oos = oos or []
    http_file = program_dir / "http" / "lives-http.json"
    if not http_file.exists():
        return []
    try:
        lives = json.loads(http_file.read_text())
    except Exception:
        return []

    redirect_map = build_redirect_map(program_dir)

    urls = []
    oos_skipped = 0
    redirect_skipped = 0
    for host, info in lives.items():
        if info.get("domain") != domain:
            continue
        if (scope or oos) and not is_in_scope(host, scope, oos):
            oos_skipped += 1
            continue
        if not is_canonical(host, redirect_map):
            redirect_skipped += 1
            continue
        url = info.get("url") or info.get("final_url") or f"https://{host}"
        if url:
            urls.append(url)

    if oos_skipped:
        print(f"     {colors.YELLOW}⏭  {oos_skipped} URL(s) skipped (out of scope){colors.RESET}")
    if redirect_skipped:
        print(f"     {colors.GRAY}⏭  {redirect_skipped} URL(s) skipped (redirect sources){colors.RESET}")

    return sorted(set(urls))


def write_urls(program_dir, urls):
    nuclei_dir = nuclei_output_dir(program_dir)
    nuclei_dir.mkdir(parents=True, exist_ok=True)
    out_file = nuclei_dir / "nuclei-urls.txt"
    out_file.write_text(
        "\n".join(urls) + ("\n" if urls else ""),
        encoding="utf-8",
    )
    return out_file


def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    non_flags = [a for a in args if not a.startswith("--")]

    if not all_mode and not non_flags:
        print("Usage: python3 nuclei_url_maker.py <domain>")
        print("       python3 nuclei_url_maker.py --all")
        sys.exit(1)

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found in database/{colors.RESET}")
            sys.exit(1)
    else:
        domain = non_flags[0].strip().lower().lstrip("*.")
        program = find_program_by_scope(domain)
        if not program:
            print(f"{colors.RED}❌ Scope '{domain}' not found{colors.RESET}")
            sys.exit(1)
        pname = program.get("program_name", "unknown")
        programs = [{
            "program_name": pname,
            "scopes": [domain],
            "path": DATABASE_DIR / sanitize_name(pname),
        }]

    total_urls = 0
    for prog in programs:
        pn = prog["program_name"]
        pd = prog["path"]

        scope, oos = load_scope_from_path(pd / "program.json")

        urls = []
        for scope_name in prog["scopes"]:
            clean = scope_name.strip().lstrip("*.").lower()
            urls.extend(extract_urls(pd, clean, scope=scope, oos=oos))
        urls = sorted(set(urls))

        if not urls:
            print(f"{colors.YELLOW}⚠️ {pn}: no HTTP URLs{colors.RESET}")
            continue

        out = write_urls(pd, urls)
        print(f"{colors.GREEN}✅ {pn}: {len(urls)} URL(s) → {out}{colors.RESET}")
        total_urls += len(urls)

    print(f"\n{colors.GREEN}✅ Done. Total URLs: {total_urls}{colors.RESET}")


if __name__ == "__main__":
    main()