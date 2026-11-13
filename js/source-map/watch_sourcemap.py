#!/usr/bin/env python3
"""
WatchTower - JS Source Map Detection
Detects exposed JavaScript source maps on in-scope HTTP hosts.

For each host, two detection methods are tried per script:

  1. Inline : fetch the tail of the JS file (Range: bytes=-5000) and look
              for ``//# sourceMappingURL=...`` at the end.
  2. Direct : HEAD ``<js_url>.map`` and check for 200 OK.

First hit wins. Stops checking a host as soon as one script reveals a map.

Writes:
  database/<program>/js/source-map/detect.json

Scope enforcement:
  - Hosts matching out_of_scope (or legacy "ooscope") are skipped.
  - OOS wins over scope.

Incremental:
  - Already-checked hosts are skipped unless --force is passed.

Usage:
  python3 watch_sourcemap.py <domain>
  python3 watch_sourcemap.py <domain> --force
  python3 watch_sourcemap.py --all
  python3 watch_sourcemap.py --all --force

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

MAX_SCRIPTS_PER_HOST = 20
MAX_HTML_BYTES = 1024 * 1024     # 1MB frontpage
TAIL_BYTES = 5000                # last 5KB of each JS (sourceMappingURL lives at the end)

# Regex to extract the map filename from a //# sourceMappingURL=... comment.
SOURCE_MAP_RE = re.compile(
    r"sourceMappingURL\s*=\s*([^\s'\"]+)",
    re.IGNORECASE,
)


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
    return program_dir / "js" / "source-map" / "detect.json"


# =========================
# Fetching
# =========================

def fetch_limited(url, max_bytes, use_tail=False):
    """
    Fetch a URL with capped bytes.
    If use_tail=True, sends Range: bytes=-<max_bytes> (last N bytes) so we
    can grab the tail of JS files without downloading the whole bundle.
    Returns (text, status, error).
    """
    headers = {"User-Agent": USER_AGENT}
    if use_tail:
        headers["Range"] = f"bytes=-{max_bytes}"

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


def head_status(url):
    """Return HTTP status code (or None on network error)."""
    try:
        r = requests.head(
            url,
            headers={"User-Agent": USER_AGENT},
            timeout=TIMEOUT,
            allow_redirects=True,
        )
        return r.status_code
    except Exception:
        return None


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
# Detection methods
# =========================

def check_inline_map(js_url):
    """
    Fetch the last TAIL_BYTES of a JS file and look for sourceMappingURL.
    Returns the full map URL (resolved against js_url) or None.
    """
    text, _, _ = fetch_limited(js_url, TAIL_BYTES, use_tail=True)
    if not text:
        return None

    m = SOURCE_MAP_RE.search(text)
    if not m:
        return None

    map_name = m.group(1).strip()
    if not map_name:
        return None

    # Skip data: URIs (inline base64 maps) — technically exposed but useless
    # for on-disk extraction. Treat as not-found for our purposes.
    if map_name.startswith("data:"):
        return None

    return urljoin(js_url, map_name)


def check_direct_map(js_url):
    """
    HEAD <js_url>.map. Returns the map URL if 200 OK, else None.
    """
    if not js_url.lower().split("?")[0].endswith(".js"):
        return None
    map_url = js_url + ".map"
    status = head_status(map_url)
    if status == 200:
        return map_url
    return None


def detect_sourcemap_on_host(url):
    """
    Returns dict:
      {
        source_map: bool,
        method: "inline" | "direct" | None,
        map_url: str | None,
        script_url: str | None,   # the JS file that revealed the map
        scripts_checked: int,
        error: str | None
      }
    """
    result = {
        "source_map": False,
        "method": None,
        "map_url": None,
        "script_url": None,
        "scripts_checked": 0,
        "error": None,
    }

    html, status, err = fetch_limited(url, MAX_HTML_BYTES)
    if html is None:
        result["error"] = err or f"status={status}"
        return result

    script_srcs = extract_script_srcs(html)
    if not script_srcs:
        return result

    seen = set()
    checked = 0

    for src in script_srcs:
        if checked >= MAX_SCRIPTS_PER_HOST:
            break

        try:
            js_url = urljoin(url, src)
            if js_url in seen:
                continue
            seen.add(js_url)
        except Exception:
            continue

        # Method A: inline sourceMappingURL
        inline_map = check_inline_map(js_url)
        if inline_map:
            result["source_map"] = True
            result["method"] = "inline"
            result["map_url"] = inline_map
            result["script_url"] = js_url
            result["scripts_checked"] = checked + 1
            return result

        # Method B: direct .js.map
        direct_map = check_direct_map(js_url)
        if direct_map:
            result["source_map"] = True
            result["method"] = "direct"
            result["map_url"] = direct_map
            result["script_url"] = js_url
            result["scripts_checked"] = checked + 1
            return result

        checked += 1

    result["scripts_checked"] = checked
    return result


# =========================
# Program processing
# =========================

def get_hosts_for_program(program_dir):
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
        if isinstance(cached, dict) and "source_map" in cached:
            per_host[host] = cached
            skipped += 1
            if cached.get("source_map"):
                positive += 1
                print(f"     {colors.GRAY}[skip] {host} → source_map=True (cached){colors.RESET}")
            else:
                print(f"     {colors.GRAY}[skip] {host} → no source_map (cached){colors.RESET}")
            continue

        print(f"     {colors.CYAN}[check] {host}{colors.RESET}")
        result = detect_sourcemap_on_host(url)
        per_host[host] = result
        checked += 1

        if result["source_map"]:
            positive += 1
            print(f"       {colors.GREEN}✅ source map exposed "
                  f"({result['method']}) → {result['map_url']}{colors.RESET}")
        else:
            if result.get("error"):
                print(f"       {colors.YELLOW}⚠️ not detected ({result['error']}){colors.RESET}")
            else:
                print(f"       {colors.GRAY}✗ no source map "
                      f"({result['scripts_checked']} script(s) checked){colors.RESET}")

    output = {
        "source_map": positive > 0,
        "program": pn,
        "timestamp": now(),
        "hosts_total": len(hosts),
        "hosts_with_source_map": positive,
        "per_host": per_host,
    }
    save_json(out_file, output)
    print(f"\n     {colors.GREEN}💾 saved → {out_file}{colors.RESET}")
    print(f"     {colors.CYAN}source_map: {output['source_map']} "
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

    print(f"{colors.CYAN}[{now()}] WatchTower — Source Map Detection"
          f"{' [Force]' if force else ''}{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_sourcemap.py <domain> [--force]")
            print("       python3 watch_sourcemap.py --all [--force]")
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
    print(f"{colors.GREEN}✅ Source map detection complete{colors.RESET}")
    print(f"{colors.GREEN}   Checked  : {total_checked}{colors.RESET}")
    if total_skipped:
        print(f"{colors.CYAN}   Skipped  : {total_skipped} (already cached){colors.RESET}")
    print(f"{colors.GREEN}   Positive : {total_positive}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")


if __name__ == "__main__":
    main()