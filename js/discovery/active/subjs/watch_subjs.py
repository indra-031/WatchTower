#!/usr/bin/env python3
"""
WatchTower - JS Discovery : SubJS (active)
Feeds every collected URL from passive + katana sources into subjs,
which fetches each URL and extracts <script src> URLs from the HTML.

Input sources (all per program, in-scope only):
  - js/discovery/passive/getjs/urls.txt
  - js/discovery/passive/gau/urls.txt
  - js/discovery/passive/sitemap/urls.txt
  - js/discovery/passive/waybackurls/urls.txt
  - js/discovery/active/katana/urls.txt
  - http/lives-http.json          (base URLs only)

Outputs:
  database/<program>/js/discovery/active/subjs/urls.txt
  database/<program>/js/discovery/active/subjs/meta.json

Incremental:
  - program-level cache. If inputs didn't change since last run,
    subjs is skipped (unless --force).
  - Input signature = sha256 of sorted input URLs (capped at MAX_INPUT_URLS).

Scope enforcement:
  - Inputs are filtered by scope before feeding subjs.
  - Results are filtered again by scope (defense in depth).
  - OOS wins over scope.

Usage:
  python3 watch_subjs.py <domain>
  python3 watch_subjs.py <domain> --force
  python3 watch_subjs.py --all
  python3 watch_subjs.py --all --force

Requires:
  subjs : go install github.com/lc/subjs@latest
"""

import sys
import json
import hashlib
import subprocess
from datetime import datetime, timedelta
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

TOOL_NAME = "subjs"
FRESH_HOURS = 24
SUBJS_TIMEOUT = 900
MAX_INPUT_URLS = 10000
MAX_URLS = 50000

INPUT_SOURCES = [
    ("passive/getjs", "getjs"),
    ("passive/gau", "gau"),
    ("passive/sitemap", "sitemap"),
    ("passive/waybackurls", "waybackurls"),
    ("active/katana", "katana"),
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


def is_fresh(ts, hours=FRESH_HOURS):
    if not ts:
        return False
    try:
        return (datetime.now() - datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")) <= timedelta(hours=hours)
    except Exception:
        return False


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
    return program_dir / "js" / "discovery" / "active" / TOOL_NAME


def collect_input_urls(program_dir, scope, oos):
    """
    Read all discovery URLs for this program.
    Returns (urls_sorted, source_breakdown).
    """
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

    # Also add base HTTP live URLs
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
    return filtered[:MAX_INPUT_URLS], breakdown


def input_signature(urls):
    """Stable hash of the input URL set, for cache invalidation."""
    h = hashlib.sha256()
    for u in sorted(set(urls)):
        h.update(u.encode("utf-8", errors="ignore"))
        h.update(b"\n")
    return h.hexdigest()[:16]


def run_subjs(input_urls):
    """Run subjs on the list. Returns list of unique JS URLs."""
    if not input_urls:
        return []

    tmp_input = Path("/tmp") / f"subjs_input_{input_signature(input_urls)}.txt"
    tmp_input.write_text("\n".join(input_urls) + "\n", encoding="utf-8")

    try:
        result = subprocess.check_output(
            ["subjs", "-i", str(tmp_input), "-c", "20", "-t", "20"],
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=SUBJS_TIMEOUT,
        )
        js_urls = list(dict.fromkeys(
            line.strip() for line in result.splitlines() if line.strip()
        ))
        return js_urls
    except FileNotFoundError:
        print(f"{colors.RED}❌ subjs not installed. "
              f"Install: go install github.com/lc/subjs@latest{colors.RESET}")
        sys.exit(1)
    except subprocess.TimeoutExpired:
        print(f"       {colors.YELLOW}⏰ subjs timeout{colors.RESET}")
        return []
    except Exception as e:
        print(f"       {colors.RED}❌ {e}{colors.RESET}")
        return []
    finally:
        try:
            tmp_input.unlink()
        except Exception:
            pass


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

    input_urls, breakdown = collect_input_urls(pd, scope, oos)

    if not input_urls:
        print(f"{colors.YELLOW}⚠️ No input URLs for {pn} "
              f"(run passive discovery + katana first){colors.RESET}\n")
        return {"ran": False, "skipped": False, "urls": 0, "input": 0}

    sig = input_signature(input_urls)

    meta = load_json(meta_file)
    prev_sig = meta.get("input_signature") if isinstance(meta, dict) else None
    prev_ts = meta.get("last_run") if isinstance(meta, dict) else None

    if not force and prev_sig == sig and is_fresh(prev_ts):
        print(f"     {colors.GRAY}[skip] inputs unchanged since {prev_ts}"
              f" ({meta.get('urls_total', 0)} JS URLs cached){colors.RESET}\n")
        return {"ran": False, "skipped": True,
                "urls": meta.get("urls_total", 0), "input": len(input_urls)}

    print(f"     {colors.CYAN}📥 input URLs: {len(input_urls)}{colors.RESET}")
    for src, cnt in breakdown.items():
        print(f"       {colors.GRAY}• {src}: {cnt}{colors.RESET}")
    print(f"     {colors.GRAY}signature: {sig}{colors.RESET}")

    js_urls_raw = run_subjs(input_urls)
    js_urls = filter_urls_by_scope(js_urls_raw, scope, oos)
    js_urls = sorted(set(js_urls))[:MAX_URLS]

    out_dir.mkdir(parents=True, exist_ok=True)
    urls_file.write_text("\n".join(js_urls) + ("\n" if js_urls else ""),
                         encoding="utf-8")

    save_json(meta_file, {
        "tool": TOOL_NAME,
        "program": pn,
        "last_run": now(),
        "input_signature": sig,
        "input_urls": len(input_urls),
        "input_breakdown": breakdown,
        "urls_total": len(js_urls),
    })

    print(f"     {colors.GREEN}✅ {len(js_urls)} JS URL(s) "
          f"(from {len(input_urls)} inputs, "
          f"{len(js_urls_raw) - len(js_urls)} OOS filtered){colors.RESET}")
    print(f"     {colors.GREEN}💾 saved → {urls_file}{colors.RESET}\n")

    return {"ran": True, "skipped": False,
            "urls": len(js_urls), "input": len(input_urls)}


# =========================
# Main
# =========================

def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    force = "--force" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — SubJS Extraction"
          f"{' [Force]' if force else ''}{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_subjs.py <domain> [--force]")
            print("       python3 watch_subjs.py --all [--force]")
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

    total_ran = 0
    total_skipped = 0
    total_js = 0

    for prog in programs:
        s = process_program(prog, force=force)
        if s["ran"]:
            total_ran += 1
        if s["skipped"]:
            total_skipped += 1
        total_js += s["urls"]

    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ SubJS extraction complete{colors.RESET}")
    print(f"{colors.GREEN}   Ran      : {total_ran}{colors.RESET}")
    if total_skipped:
        print(f"{colors.CYAN}   Skipped  : {total_skipped} (inputs unchanged){colors.RESET}")
    print(f"{colors.GREEN}   JS URLs  : {total_js}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")


if __name__ == "__main__":
    main()