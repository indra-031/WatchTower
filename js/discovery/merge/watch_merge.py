#!/usr/bin/env python3
"""
WatchTower - JS Discovery : Merge
Aggregates every discovered URL across all passive and active tools
into a single deduplicated, scope-filtered list.

Input sources (all per program):
  - js/discovery/passive/getjs/urls.txt
  - js/discovery/passive/gau/urls.txt
  - js/discovery/passive/sitemap/urls.txt
  - js/discovery/passive/waybackurls/urls.txt
  - js/discovery/active/katana/urls.txt
  - js/discovery/active/subjs/urls.txt
  - http/lives-http.json               (base URLs)

Writes:
  database/<program>/js/discovery/merge/urls.txt
  database/<program>/js/discovery/merge/meta.json

Scope enforcement:
  - Only in-scope URLs survive (OOS wins over scope).
  - Defense in depth: each source is already filtered at write time.

Incremental:
  - sha256 of the sorted URL set is stored in meta.json. If inputs
    haven't changed since last run, merging is skipped (unless --force).

Usage:
  python3 watch_merge.py <domain>
  python3 watch_merge.py <domain> --force
  python3 watch_merge.py --all
  python3 watch_merge.py --all --force

Requires:
  Only Python stdlib.
"""

import sys
import json
import hashlib
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


# =========================
# Project root discovery
# =========================

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


# =========================
# Configuration
# =========================

TOOL_NAME = "merge"
MAX_URLS = 100000

INPUT_SOURCES = [
    ("passive/getjs", "getjs"),
    ("passive/gau", "gau"),
    ("passive/sitemap", "sitemap"),
    ("passive/waybackurls", "waybackurls"),
    ("active/katana", "katana"),
    ("active/subjs", "subjs"),
]


# =========================
# Helpers
# =========================

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize(name):
    return (name.strip().lower()
            .replace(" ", "-").replace("/", "-")
            .replace("\\", "-").replace(":", "-"))


def load_json(path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")


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


def url_hostname(url):
    try:
        return (urlparse(url).hostname or "").lower()
    except Exception:
        return ""


def filter_urls_by_scope(urls, scope, oos):
    if not (scope or oos):
        return urls
    return [u for u in urls if url_hostname(u) and is_in_scope(url_hostname(u), scope, oos)]


def output_dir(program_dir):
    return program_dir / "js" / "discovery" / TOOL_NAME


def collect_all_urls(program_dir, scope, oos):
    """Return (urls_sorted, source_breakdown)."""
    all_urls = set()
    breakdown = {}
    js_dir = program_dir / "js" / "discovery"

    for rel_path, label in INPUT_SOURCES:
        f = js_dir / rel_path / "urls.txt"
        if not f.exists():
            continue
        try:
            lines = f.read_text(encoding="utf-8").splitlines()
        except Exception:
            continue
        count = 0
        for line in lines:
            line = line.strip()
            if not line or not line.startswith("http"):
                continue
            all_urls.add(line)
            count += 1
        if count:
            breakdown[label] = count

    # Base HTTP live URLs
    lf = program_dir / "http" / "lives-http.json"
    if lf.exists():
        try:
            lives = json.loads(lf.read_text())
            count = 0
            for host, info in lives.items():
                if info.get("status", "alive") != "alive":
                    continue
                url = info.get("url") or info.get("final_url") or f"https://{host}"
                if url:
                    all_urls.add(url)
                    count += 1
            if count:
                breakdown["lives-http"] = count
        except Exception:
            pass

    filtered = filter_urls_by_scope(sorted(all_urls), scope, oos)
    return filtered[:MAX_URLS], breakdown


def input_signature(urls):
    h = hashlib.sha256()
    for u in sorted(set(urls)):
        h.update(u.encode("utf-8", errors="ignore"))
        h.update(b"\n")
    return h.hexdigest()[:16]


# =========================
# Program processing
# =========================

def process_program(program, force=False):
    pn = program["program_name"]
    pd = program["path"]
    out_dir = output_dir(pd)
    urls_file = out_dir / "urls.txt"
    meta_file = out_dir / "meta.json"

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    scope, oos = load_scope_from_path(pd / "program.json")

    urls, breakdown = collect_all_urls(pd, scope, oos)

    if not urls:
        print(f"{colors.YELLOW}⚠️ No URLs to merge for {pn} "
              f"(run passive/active discovery first){colors.RESET}\n")
        return {"ran": False, "skipped": False, "urls": 0}

    sig = input_signature(urls)

    meta = load_json(meta_file)
    prev_sig = meta.get("input_signature") if isinstance(meta, dict) else None

    if not force and prev_sig == sig and urls_file.exists():
        print(f"     {colors.GRAY}[skip] inputs unchanged "
              f"({meta.get('urls_total', 0)} URLs cached){colors.RESET}\n")
        return {"ran": False, "skipped": True, "urls": meta.get("urls_total", 0)}

    print(f"     {colors.CYAN}📥 sources:{colors.RESET}")
    for src, cnt in breakdown.items():
        print(f"       {colors.GRAY}• {src}: {cnt}{colors.RESET}")

    out_dir.mkdir(parents=True, exist_ok=True)
    urls_file.write_text("\n".join(urls) + ("\n" if urls else ""), encoding="utf-8")

    save_json(meta_file, {
        "tool": TOOL_NAME,
        "program": pn,
        "timestamp": now(),
        "input_signature": sig,
        "urls_total": len(urls),
        "breakdown": breakdown,
    })

    print(f"     {colors.GREEN}✅ {len(urls)} unique URL(s){colors.RESET}")
    print(f"     {colors.GREEN}💾 saved → {urls_file}{colors.RESET}\n")

    return {"ran": True, "skipped": False, "urls": len(urls)}


# =========================
# Main
# =========================

def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    force = "--force" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — Merge Discovery URLs"
          f"{' [Force]' if force else ''}{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_merge.py <domain> [--force]")
            print("       python3 watch_merge.py --all [--force]")
            sys.exit(1)
        domain = non_flags[0].strip().lower().lstrip("*.")
        program = find_program_by_scope(domain)
        if not program:
            print(f"{colors.RED}❌ Scope '{domain}' not found{colors.RESET}")
            sys.exit(1)
        pname = program.get("program_name", "unknown")
        programs = [{
            "program_name": pname,
            "scopes": [domain],
            "path": DATABASE_DIR / sanitize(pname),
        }]

    total_ran = total_skipped = total_urls = 0
    for prog in programs:
        s = process_program(prog, force=force)
        if s["ran"]:
            total_ran += 1
        if s["skipped"]:
            total_skipped += 1
        total_urls += s["urls"]

    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ Merge complete{colors.RESET}")
    print(f"{colors.GREEN}   Ran      : {total_ran}{colors.RESET}")
    if total_skipped:
        print(f"{colors.CYAN}   Skipped  : {total_skipped} (inputs unchanged){colors.RESET}")
    print(f"{colors.GREEN}   URLs     : {total_urls}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")


if __name__ == "__main__":
    main()