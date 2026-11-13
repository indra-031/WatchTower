#!/usr/bin/env python3
"""
WatchTower - Content Discovery

Merges every URL/path/endpoint/parameter the pipeline has discovered into
a single per-program content set. Handles the WWW/bare redirect problem
by canonicalizing hostnames against httpx's final_url map.

Sources merged:
  Discovery URLs
    js/discovery/passive/{getjs,gau,sitemap,waybackurls}/urls.txt
    js/discovery/active/{katana,subjs}/urls.txt
    js/discovery/merge/urls.txt
  Extraction
    js/extraction/merge/urls-merge.txt
    js/extraction/merge/links-merge.txt
    js/extraction/merge/urls-with-param.txt
    js/extraction/xnlinkfinder/links.txt
  Paths / Endpoints
    js/extraction/merge/paths-merge.txt
    js/extraction/merge/endpoints-merge.txt
  Parameters
    js/extraction/merge/parameters-merge.txt
    js/extraction/xnlinkfinder/parameters.txt

Redirect handling:
  - Reads http/lives-http.json, extracts `final_url` per host.
  - Builds map: redirect_from_host → redirect_to_host.
  - Every URL whose host is in the map is rewritten to the final host.
  - Example: https://www.test.com/x -> https://test.com/x
  - This eliminates duplicate content (www vs bare).

Outputs (database/<program>/content/):
  urls.txt              all unique URLs (canonicalized)
  urls-with-param.txt   subset containing `?`
  js-urls.txt           only .js URLs
  html-urls.txt         only .html/.htm URLs
  paths.txt             unique paths (from paths-merge + parsed from URLs)
  endpoints.txt         unique endpoints (from endpoints-merge)
  parameters.txt        unique parameter names
  meta.json             stats + redirect map

Usage:
  python3 watch_content_discovery.py <domain>
  python3 watch_content_discovery.py --all
"""

import sys
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urlunparse


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


# URL sources — only lines starting with `http` are kept
URL_SOURCES = [
    "discovery/passive/getjs/urls.txt",
    "discovery/passive/gau/urls.txt",
    "discovery/passive/sitemap/urls.txt",
    "discovery/passive/waybackurls/urls.txt",
    "discovery/active/katana/urls.txt",
    "discovery/active/subjs/urls.txt",
    "discovery/merge/urls.txt",
    "extraction/merge/urls-merge.txt",
    "extraction/merge/links-merge.txt",
    "extraction/merge/urls-with-param.txt",
    "extraction/xnlinkfinder/links.txt",
]

# Path/endpoint sources — lines starting with `/`
PATH_SOURCES = [
    "extraction/merge/paths-merge.txt",
    "extraction/merge/endpoints-merge.txt",
]

# Parameter sources — plain names (no URL parsing)
PARAM_SOURCES = [
    "extraction/merge/parameters-merge.txt",
    "extraction/xnlinkfinder/parameters.txt",
]


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


def read_lines(path):
    if not path.exists():
        return []
    try:
        return [l.strip() for l in path.read_text(errors="ignore").splitlines() if l.strip()]
    except Exception:
        return []


# =========================
# URL canonicalization
# =========================

def build_redirect_map(program_dir):
    """
    Return {from_host: to_host} based on httpx final_url values.

    A host appears as a key only if its final_url points to a different
    hostname. Example: www.test.com/foo redirects to test.com/foo
    → {"www.test.com": "test.com"}.
    """
    lives_file = program_dir / "http" / "lives-http.json"
    if not lives_file.exists():
        return {}
    try:
        lives = json.loads(lives_file.read_text())
    except Exception:
        return {}

    redirect_map = {}
    for host, info in lives.items():
        final_url = info.get("final_url") or ""
        if not final_url:
            continue
        try:
            final_host = (urlparse(final_url).hostname or "").lower()
        except Exception:
            continue
        if not final_host:
            continue
        h = host.lower()
        if final_host != h:
            redirect_map[h] = final_host
    return redirect_map


def normalize_url(url):
    """
    Normalize scheme/host to lowercase, ensure path defaults to "/".
    Returns None if the URL is malformed.
    """
    try:
        p = urlparse(url)
        if not p.scheme or not p.hostname:
            return None
        scheme = p.scheme.lower()
        host = p.hostname.lower()
        path = p.path or "/"

        netloc = host
        if p.port and not (
            (scheme == "http" and p.port == 80) or
            (scheme == "https" and p.port == 443)
        ):
            netloc = f"{host}:{p.port}"

        return urlunparse((scheme, netloc, path, p.params, p.query, p.fragment))
    except Exception:
        return None


def canonicalize_url(url, redirect_map):
    """
    Normalize and rewrite host if it appears in redirect_map.
    Returns None if malformed.
    """
    normalized = normalize_url(url)
    if not normalized:
        return None
    try:
        p = urlparse(normalized)
        host = p.hostname
        if host and host in redirect_map:
            new_host = redirect_map[host]
            netloc = new_host
            if p.port and not (
                (p.scheme == "http" and p.port == 80) or
                (p.scheme == "https" and p.port == 443)
            ):
                netloc = f"{new_host}:{p.port}"
            return urlunparse((p.scheme, netloc, p.path, p.params, p.query, p.fragment))
        return normalized
    except Exception:
        return None


def extract_path(url):
    """Return the pathname part of a URL, or None."""
    try:
        p = urlparse(url)
        return p.path or "/"
    except Exception:
        return None


# =========================
# Program processing
# =========================

def process_program(program):
    pn = program["program_name"]
    pd = program["path"]
    js_dir = pd / "js"
    out_dir = pd / "content"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    redirect_map = build_redirect_map(pd)
    if redirect_map:
        print(f"     {colors.CYAN}redirect map:{colors.RESET}")
        for frm, to in redirect_map.items():
            print(f"       {colors.GRAY}{frm} → {to}{colors.RESET}")

    # ---- URLs ----
    raw_urls = set()
    url_source_counts = {}
    for rel in URL_SOURCES:
        lines = read_lines(js_dir / rel)
        keep = [l for l in lines if l.startswith("http")]
        for u in keep:
            raw_urls.add(u)
        if keep:
            url_source_counts[rel] = len(keep)

    # Canonicalize
    canonical = set()
    dropped = 0
    for u in raw_urls:
        c = canonicalize_url(u, redirect_map)
        if c:
            canonical.add(c)
        else:
            dropped += 1

    # ---- paths / endpoints ----
    raw_paths = set()
    for rel in PATH_SOURCES:
        for line in read_lines(js_dir / rel):
            if line.startswith("/"):
                raw_paths.add(line)
    # Also extract paths from URLs
    for u in canonical:
        p = extract_path(u)
        if p and p != "/":
            raw_paths.add(p)

    # ---- parameters ----
    params = set()
    for rel in PARAM_SOURCES:
        for line in read_lines(js_dir / rel):
            params.add(line)

    # ---- categorize URLs ----
    js_urls = set()
    html_urls = set()
    with_param = set()
    for u in canonical:
        path = u.lower().split("?", 1)[0]
        if path.endswith(".js"):
            js_urls.add(u)
        elif path.endswith((".html", ".htm")):
            html_urls.add(u)
        if "?" in u:
            with_param.add(u)

    # ---- write outputs ----
    def _write(path, items):
        path.write_text("\n".join(sorted(items)) + ("\n" if items else ""),
                        encoding="utf-8")

    _write(out_dir / "urls.txt", canonical)
    _write(out_dir / "urls-with-param.txt", with_param)
    _write(out_dir / "js-urls.txt", js_urls)
    _write(out_dir / "html-urls.txt", html_urls)
    _write(out_dir / "paths.txt", raw_paths)
    _write(out_dir / "endpoints.txt", raw_paths)  # same for now
    _write(out_dir / "parameters.txt", params)

    save_json(out_dir / "meta.json", {
        "program": pn,
        "timestamp": now(),
        "sources": url_source_counts,
        "redirect_map": redirect_map,
        "counts": {
            "urls": len(canonical),
            "urls_with_param": len(with_param),
            "js_urls": len(js_urls),
            "html_urls": len(html_urls),
            "paths": len(raw_paths),
            "parameters": len(params),
        },
        "raw_urls": len(raw_urls),
        "duplicates_collapsed": len(raw_urls) - len(canonical) + dropped,
        "dropped_malformed": dropped,
    })

    print()
    print(f"     {colors.CYAN}📊 Content:{colors.RESET}")
    print(f"       urls              : {len(canonical)}")
    print(f"       urls_with_param   : {len(with_param)}")
    print(f"       js_urls           : {len(js_urls)}")
    print(f"       html_urls         : {len(html_urls)}")
    print(f"       paths             : {len(raw_paths)}")
    print(f"       parameters        : {len(params)}")
    if redirect_map:
        print(f"       {colors.GRAY}canonicalized via redirect_map: "
              f"{len(raw_urls) - len(canonical) + dropped}{colors.RESET}")
    print(f"     {colors.GREEN}💾 saved → {out_dir}{colors.RESET}\n")

    return {
        "urls": len(canonical),
        "urls_with_param": len(with_param),
        "js_urls": len(js_urls),
        "html_urls": len(html_urls),
        "paths": len(raw_paths),
        "parameters": len(params),
    }


def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — Content Discovery{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_content_discovery.py <domain>")
            print("       python3 watch_content_discovery.py --all")
            sys.exit(1)
        domain = non_flags[0].strip().lower().lstrip("*.")
        program = find_program_by_scope(domain)
        if not program:
            print(f"{colors.RED}❌ Scope '{domain}' not found{colors.RESET}")
            sys.exit(1)
        pname = program.get("program_name", "unknown")
        programs = [{"program_name": pname, "path": DATABASE_DIR / sanitize(pname)}]

    totals = {"urls": 0, "urls_with_param": 0, "js_urls": 0,
              "html_urls": 0, "paths": 0, "parameters": 0}
    for prog in programs:
        r = process_program(prog)
        for k in totals:
            totals[k] += r[k]

    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ Content discovery complete{colors.RESET}")
    print(f"{colors.GREEN}   URLs              : {totals['urls']}{colors.RESET}")
    print(f"{colors.GREEN}   URLs with param   : {totals['urls_with_param']}{colors.RESET}")
    print(f"{colors.GREEN}   JS URLs           : {totals['js_urls']}{colors.RESET}")
    print(f"{colors.GREEN}   HTML URLs         : {totals['html_urls']}{colors.RESET}")
    print(f"{colors.GREEN}   Paths             : {totals['paths']}{colors.RESET}")
    print(f"{colors.GREEN}   Parameters        : {totals['parameters']}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")


if __name__ == "__main__":
    main()