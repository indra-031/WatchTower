#!/usr/bin/env python3
"""
WatchTower - JS Webpack Detection
Detects whether hosts use webpack-bundled JavaScript.

For each in-scope HTTP host:
  - Fetch the frontpage (capped at 1MB)
  - Check HTML itself for webpack runtime markers
  - Parse <script src> tags (BeautifulSoup, or regex fallback)
  - Fetch first N JS files (Range request, capped at 200KB each)
  - Report which patterns matched (evidence)

Writes:
  database/<program>/js/web-pack/detect.json

Scope enforcement:
  - Hosts matching out_of_scope (or legacy "ooscope") are skipped.
  - OOS wins over scope.
  - Defense in depth: lives-http.json is filtered at write time,
    but hosts are filtered again here.

Incremental:
  - By default, already-checked hosts are skipped (reuse cached result).
  - --force re-checks every host.

Usage:
  python3 watch_webpack.py <domain>
  python3 watch_webpack.py <domain> --force
  python3 watch_webpack.py --all
  python3 watch_webpack.py --all --force

Requires:
  pip install beautifulsoup4 requests
"""

import sys
import json
import re
import requests
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin

try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


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

TIMEOUT = 10
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36"
)

WEBPACK_PATTERNS = [
    "__webpack_require__",
    "webpackChunk",
    "webpackJsonp",
    "window.webpack",
    "webpack_require",
]

MAX_SCRIPTS_PER_HOST = 20
MAX_JS_BYTES = 200 * 1024       # 200KB per JS file (Range request)
MAX_HTML_BYTES = 1024 * 1024    # 1MB per HTML page


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


def detect_output_path(program_dir):
    return program_dir / "js" / "web-pack" / "detect.json"


# =========================
# Fetching
# =========================

def fetch_limited(url, max_bytes, use_range=False):
    """
    Fetch a URL, capping total bytes.
    Returns (text, status_code, error).

    If use_range=True, sends a Range header so the server can send partial
    content (saves bandwidth for large JS bundles).
    """
    headers = {"User-Agent": USER_AGENT}
    if use_range:
        headers["Range"] = f"bytes=0-{max_bytes - 1}"

    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT, stream=True,
                         allow_redirects=True)
        status = r.status_code
        if status not in (200, 206):
            return None, status, f"status={status}"

        content = b""
        for chunk in r.iter_content(8192):
            content += chunk
            if len(content) >= max_bytes:
                break

        return content.decode("utf-8", errors="ignore"), status, None
    except requests.Timeout:
        return None, None, "timeout"
    except requests.ConnectionError:
        return None, None, "connection error"
    except Exception as e:
        return None, None, str(e)


def extract_script_srcs(html):
    """Extract <script src> values. Uses BS4 if available, regex fallback."""
    if HAS_BS4:
        try:
            soup = BeautifulSoup(html, "html.parser")
            return [s["src"] for s in soup.find_all("script", src=True)]
        except Exception:
            pass

    pattern = r'<script[^>]+src=["\']([^"\']+)["\']'
    return re.findall(pattern, html, re.IGNORECASE)


# =========================
# Detection
# =========================

def check_patterns(text):
    """Return list of matched webpack patterns (empty if none)."""
    return [p for p in WEBPACK_PATTERNS if p in text]


def detect_webpack_on_host(url):
    """
    Returns dict:
      {webpack: bool, evidence: [str], scripts_checked: int, error: str|None}
    """
    result = {"webpack": False, "evidence": [], "scripts_checked": 0, "error": None}

    html, status, err = fetch_limited(url, MAX_HTML_BYTES)
    if html is None:
        result["error"] = err or f"status={status}"
        return result

    # Check the HTML itself first
    matched = check_patterns(html)
    if matched:
        result["webpack"] = True
        result["evidence"] = matched
        return result

    # Parse <script src> tags
    script_srcs = extract_script_srcs(html)
    if not script_srcs:
        return result

    # Try the first N unique scripts
    seen = set()
    checked = 0
    all_matched = set()

    for src in script_srcs:
        if checked >= MAX_SCRIPTS_PER_HOST:
            break

        try:
            js_url = urljoin(url, src)
            if js_url in seen:
                continue
            seen.add(js_url)

            js_text, _, _ = fetch_limited(js_url, MAX_JS_BYTES, use_range=True)
            checked += 1

            if js_text:
                hits = check_patterns(js_text)
                if hits:
                    all_matched.update(hits)
                    break
        except Exception:
            continue

    result["scripts_checked"] = checked
    if all_matched:
        result["webpack"] = True
        result["evidence"] = sorted(all_matched)

    return result


# =========================
# Program processing
# =========================

def get_hosts_for_program(program_dir):
    """Return [(host, url), ...] from lives-http.json, alive, in-scope."""
    lf = program_dir / "http" / "lives-http.json"
    if not lf.exists():
        return []
    try:
        lives = json.loads(lf.read_text())
    except Exception:
        return []

    scope, oos = load_scope_from_path(program_dir / "program.json")

    hosts = []
    for host, info in lives.items():
        if info.get("status", "alive") != "alive":
            continue
        if (scope or oos) and not is_in_scope(host, scope, oos):
            continue
        url = info.get("url") or info.get("final_url") or f"https://{host}"
        if url:
            hosts.append((host, url))
    return hosts


def process_program(program, force=False):
    pn = program["program_name"]
    pd = program["path"]
    out_file = detect_output_path(pd)

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    hosts = get_hosts_for_program(pd)
    if not hosts:
        print(f"{colors.YELLOW}⚠️ No in-scope HTTP hosts for {pn}{colors.RESET}\n")
        return {"checked": 0, "positive": 0, "skipped": 0}

    existing = load_json(out_file)
    if not isinstance(existing, dict):
        existing = {}
    per_host_existing = existing.get("per_host", {})
    if not isinstance(per_host_existing, dict):
        per_host_existing = {}

    per_host = {}
    checked = 0
    skipped = 0
    positive = 0

    for host, url in hosts:
        cached = per_host_existing.get(host) if not force else None
        if isinstance(cached, dict) and "webpack" in cached:
            per_host[host] = cached
            skipped += 1
            if cached.get("webpack"):
                positive += 1
                print(f"     {colors.GRAY}[skip] {host} → webpack=True (cached){colors.RESET}")
            else:
                print(f"     {colors.GRAY}[skip] {host} → no webpack (cached){colors.RESET}")
            continue

        print(f"     {colors.CYAN}[check] {host}{colors.RESET}")
        result = detect_webpack_on_host(url)
        per_host[host] = result
        checked += 1

        if result["webpack"]:
            positive += 1
            ev = ", ".join(result["evidence"])
            print(f"       {colors.GREEN}✅ webpack detected ({ev}){colors.RESET}")
        else:
            if result.get("error"):
                print(f"       {colors.YELLOW}⚠️ not detected ({result['error']}){colors.RESET}")
            else:
                print(f"       {colors.GRAY}✗ no webpack{colors.RESET}")

    output = {
        "webpack": positive > 0,
        "program": pn,
        "timestamp": now(),
        "hosts_total": len(hosts),
        "hosts_with_webpack": positive,
        "per_host": per_host,
    }
    save_json(out_file, output)
    print(f"\n     {colors.GREEN}💾 saved → {out_file}{colors.RESET}")
    print(f"     {colors.CYAN}webpack: {output['webpack']} "
          f"({positive}/{len(hosts)} hosts){colors.RESET}\n")

    return {"checked": checked, "positive": positive, "skipped": skipped}


# =========================
# Main
# =========================

def main():
    if not HAS_BS4:
        print(f"{colors.YELLOW}⚠️ BeautifulSoup not installed, using regex fallback.{colors.RESET}")
        print(f"{colors.GRAY}   pip install beautifulsoup4{colors.RESET}\n")

    args = sys.argv[1:]
    all_mode = "--all" in args
    force = "--force" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — Webpack Detection"
          f"{' [Force]' if force else ''}{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_webpack.py <domain> [--force]")
            print("       python3 watch_webpack.py --all [--force]")
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

    total_checked = 0
    total_positive = 0
    total_skipped = 0

    for prog in programs:
        stats = process_program(prog, force=force)
        total_checked += stats["checked"]
        total_positive += stats["positive"]
        total_skipped += stats["skipped"]

    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ Webpack detection complete{colors.RESET}")
    print(f"{colors.GREEN}   Checked  : {total_checked}{colors.RESET}")
    if total_skipped:
        print(f"{colors.CYAN}   Skipped  : {total_skipped} (already cached){colors.RESET}")
    print(f"{colors.GREEN}   Positive : {total_positive}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")


if __name__ == "__main__":
    main()