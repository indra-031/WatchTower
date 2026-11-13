#!/usr/bin/env python3
"""
WatchTower - JS Download
Downloads discovered .js and .html/.htm files to disk, keyed by
md5(url) so filenames are stable across runs.

Additionally, every live host in http/lives-http.json is treated as an
HTML page to download (its front page), because those URLs usually don't
end in .html — e.g. https://thezodd.com. Without this, sites that only
have a single front page would never be downloaded or extracted from.

Redirect sources (hosts whose httpx final_url points to another host) are
skipped — their content is downloaded once via the canonical host.

Inputs:
  database/<program>/js/discovery/merge/urls.txt
  database/<program>/http/lives-http.json    (front-page roots)

Outputs:
  database/<program>/js/download/js/<md5>.js
  database/<program>/js/download/html/<md5>.html
  database/<program>/js/download/hash-map/js-hash-map.txt
  database/<program>/js/download/hash-map/html-hash-map.txt
  database/<program>/js/download/meta.json

Safety:
  - Files larger than MAX_FILE_BYTES (5MB) are skipped before writing.
  - Total file count is capped at MAX_FILES (10000).
  - Parallel downloads: 20 workers, 15s timeout.
  - Scope + redirect re-checked on every URL.

Incremental:
  - If a URL's md5 is already in the hash map and the file exists, skip
    unless --force.

Usage:
  python3 watch_download.py <domain>
  python3 watch_download.py <domain> --force
  python3 watch_download.py --all
  python3 watch_download.py --all --force

Requires:
  pip install requests
"""

import sys
import json
import hashlib
import requests
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock


try:
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


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
from configs.hosts import build_redirect_map, is_canonical


# =========================
# Configuration
# =========================

MAX_FILE_BYTES = 5 * 1024 * 1024
MAX_FILES = 10000
TIMEOUT = 15
WORKERS = 20
USER_AGENT = "Mozilla/5.0 (compatible; WatchTower-Downloader/1.0)"
JS_EXTENSIONS = (".js",)
HTML_EXTENSIONS = (".html", ".htm")


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


def hash_name(value):
    return hashlib.md5(value.encode()).hexdigest()


def url_kind(url):
    path = url.lower().split("?", 1)[0]
    if path.endswith(JS_EXTENSIONS):
        return "js"
    if path.endswith(HTML_EXTENSIONS):
        return "html"
    return None


def load_existing_map(map_file):
    hashes = set()
    if not map_file.exists():
        return hashes
    try:
        for line in map_file.read_text(encoding="utf-8").splitlines():
            parts = line.strip().split(" ", 1)
            if parts and parts[0]:
                hashes.add(parts[0])
    except Exception:
        pass
    return hashes


# =========================
# Download worker
# =========================

def download_one(session, url, kind, out_dir, map_file, lock, stats):
    try:
        file_hash = hash_name(url)
        extension = "js" if kind == "js" else "html"
        file_path = out_dir / f"{file_hash}.{extension}"

        if file_path.exists() and file_path.stat().st_size > 0:
            with lock:
                stats["skipped"] += 1
            return True

        r = session.get(url, timeout=TIMEOUT, verify=False, stream=True)

        with lock:
            stats[f"status_{r.status_code}"] = stats.get(f"status_{r.status_code}", 0) + 1

        if r.status_code != 200:
            return False

        cl = r.headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > MAX_FILE_BYTES:
            with lock:
                stats["too_large"] += 1
            return False

        content = b""
        aborted = False
        for chunk in r.iter_content(8192):
            if not chunk:
                continue
            content += chunk
            if len(content) > MAX_FILE_BYTES:
                aborted = True
                break

        if aborted:
            with lock:
                stats["too_large"] += 1
            return False

        if not content:
            with lock:
                stats["empty"] += 1
            return False

        out_dir.mkdir(parents=True, exist_ok=True)
        file_path.write_bytes(content)

        with lock:
            with map_file.open("a", encoding="utf-8") as m:
                m.write(f"{file_hash} {url}\n")
            stats["downloaded"] += 1
            stats["bytes"] = stats.get("bytes", 0) + len(content)

        return True

    except requests.Timeout:
        with lock:
            stats["timeout"] += 1
        return False
    except requests.ConnectionError:
        with lock:
            stats["error"] += 1
        return False
    except Exception:
        with lock:
            stats["error"] += 1
        return False


# =========================
# Program processing
# =========================

def process_program(program, force=False):
    pn = program["program_name"]
    pd = program["path"]

    merge_file = pd / "js" / "discovery" / "merge" / "urls.txt"
    if not merge_file.exists():
        print(f"{colors.YELLOW}⚠️ No merge/urls.txt for {pn} "
              f"(run watch_merge.py first){colors.RESET}\n")
        return None

    scope, oos = load_scope_from_path(pd / "program.json")
    redirect_map = build_redirect_map(pd)

    js_urls, html_urls = [], []
    oos_skipped = 0
    redirect_skipped = 0
    try:
        for line in merge_file.read_text(encoding="utf-8").splitlines():
            url = line.strip()
            if not url or not url.startswith("http"):
                continue
            url_host = url_hostname(url)
            if (scope or oos) and not is_in_scope(url_host, scope, oos):
                oos_skipped += 1
                continue
            if not is_canonical(url_host, redirect_map):
                redirect_skipped += 1
                continue
            kind = url_kind(url)
            if kind == "js":
                js_urls.append(url)
            elif kind == "html":
                html_urls.append(url)
    except Exception as e:
        print(f"{colors.RED}❌ Failed to read merge file: {e}{colors.RESET}")
        return None

    # Add each live host's root URL as an HTML page (non-redirect only).
    lives_file = pd / "http" / "lives-http.json"
    added_roots = 0
    if lives_file.exists():
        try:
            lives_data = json.loads(lives_file.read_text())
            for host, info in lives_data.items():
                if info.get("status", "alive") != "alive":
                    continue
                if (scope or oos) and not is_in_scope(host, scope, oos):
                    continue
                if not is_canonical(host, redirect_map):
                    continue
                root_url = info.get("url") or info.get("final_url") or f"https://{host}"
                if root_url and root_url not in html_urls:
                    html_urls.append(root_url)
                    added_roots += 1
        except Exception:
            pass

    if not js_urls and not html_urls:
        print(f"{colors.BLUE}{'='*60}{colors.RESET}")
        print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
        print(f"{colors.BLUE}{'='*60}{colors.RESET}")
        print(f"{colors.YELLOW}⚠️ No .js/.html URLs to download{colors.RESET}")
        if oos_skipped:
            print(f"     {colors.GRAY}⏭  {oos_skipped} URL(s) skipped (out of scope){colors.RESET}")
        if redirect_skipped:
            print(f"     {colors.GRAY}⏭  {redirect_skipped} URL(s) skipped (redirect sources){colors.RESET}")
        print()
        return {"js": 0, "html": 0, "skipped": 0, "error": 0}

    total = len(js_urls) + len(html_urls)
    if total > MAX_FILES:
        keep = MAX_FILES
        print(f"{colors.YELLOW}⚠️ {pn}: capping at {keep}/{total} files{colors.RESET}")
        if len(js_urls) > keep:
            js_urls = js_urls[:keep]
            html_urls = []
        else:
            remaining = keep - len(js_urls)
            html_urls = html_urls[:remaining]

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"     {colors.CYAN}📥 JS: {len(js_urls)}, "
          f"HTML: {len(html_urls)}{colors.RESET}")
    if added_roots:
        print(f"     {colors.GRAY}+{added_roots} live host root(s) added as HTML{colors.RESET}")
    if oos_skipped:
        print(f"     {colors.GRAY}⏭  {oos_skipped} URL(s) skipped (out of scope){colors.RESET}")
    if redirect_skipped:
        print(f"     {colors.GRAY}⏭  {redirect_skipped} URL(s) skipped (redirect sources){colors.RESET}")

    download_dir = pd / "js" / "download"
    js_dir = download_dir / "js"
    html_dir = download_dir / "html"
    map_dir = download_dir / "hash-map"
    js_dir.mkdir(parents=True, exist_ok=True)
    html_dir.mkdir(parents=True, exist_ok=True)
    map_dir.mkdir(parents=True, exist_ok=True)

    js_map = map_dir / "js-hash-map.txt"
    html_map = map_dir / "html-hash-map.txt"
    if not js_map.exists():
        js_map.write_text("", encoding="utf-8")
    if not html_map.exists():
        html_map.write_text("", encoding="utf-8")

    existing_js = set() if force else load_existing_map(js_map)
    existing_html = set() if force else load_existing_map(html_map)

    def precheck(url, existing, out_dir, extension):
        if force:
            return False
        h = hash_name(url)
        if h in existing and (out_dir / f"{h}.{extension}").exists():
            return True
        return False

    js_todo = [u for u in js_urls if not precheck(u, existing_js, js_dir, "js")]
    html_todo = [u for u in html_urls if not precheck(u, existing_html, html_dir, "html")]

    already_skipped = (len(js_urls) - len(js_todo)) + (len(html_urls) - len(html_todo))
    if already_skipped:
        print(f"     {colors.GRAY}⏭  {already_skipped} already downloaded{colors.RESET}")

    if not js_todo and not html_todo:
        print(f"     {colors.GREEN}✅ Nothing to download{colors.RESET}\n")
        return {"js": 0, "html": 0, "skipped": already_skipped, "error": 0}

    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    lock = Lock()
    stats = {"downloaded": 0, "skipped": already_skipped,
             "error": 0, "timeout": 0, "too_large": 0, "empty": 0, "bytes": 0}

    def run_batch(urls, kind, out_dir, map_file, label):
        if not urls:
            return
        total_urls = len(urls)
        print(f"     {colors.CYAN}⬇️  {label}: {total_urls} file(s){colors.RESET}")
        with ThreadPoolExecutor(max_workers=WORKERS) as ex:
            futures = [
                ex.submit(download_one, session, u, kind, out_dir, map_file, lock, stats)
                for u in urls
            ]
            done = 0
            for fut in as_completed(futures):
                done += 1
                if done % 50 == 0:
                    print(f"\r       {colors.GRAY}... {done}/{total_urls} processed, "
                          f"{stats['downloaded']} saved{colors.RESET}",
                          end="", flush=True)
        print()

    run_batch(js_todo, "js", js_dir, js_map, "JS")
    run_batch(html_todo, "html", html_dir, html_map, "HTML")

    print(f"\n     {colors.GREEN}📊 Status:{colors.RESET}")
    print(f"       {colors.GREEN}downloaded: {stats['downloaded']}{colors.RESET}")
    print(f"       {colors.GRAY}skipped   : {stats['skipped']}{colors.RESET}")
    print(f"       {colors.GRAY}empty     : {stats['empty']}{colors.RESET}")
    print(f"       {colors.GRAY}too large : {stats['too_large']}{colors.RESET}")
    print(f"       {colors.YELLOW}timeout   : {stats['timeout']}{colors.RESET}")
    print(f"       {colors.RED}error     : {stats['error']}{colors.RESET}")

    status_keys = sorted([k for k in stats if k.startswith("status_")])
    if status_keys:
        print(f"     {colors.CYAN}📊 HTTP status codes:{colors.RESET}")
        for k in status_keys:
            code = k.replace("status_", "")
            print(f"       {colors.GRAY}{code}: {stats[k]}{colors.RESET}")

    total_bytes = stats.get("bytes", 0)
    if total_bytes > 0:
        mb = total_bytes / (1024 * 1024)
        print(f"     {colors.CYAN}💾 total bytes: {mb:.2f} MB{colors.RESET}")

    save_json(download_dir / "meta.json", {
        "program": pn,
        "timestamp": now(),
        "js_total": len(js_urls),
        "html_total": len(html_urls),
        "oos_skipped": oos_skipped,
        "redirect_skipped": redirect_skipped,
        "downloaded": stats["downloaded"],
        "skipped": stats["skipped"],
        "empty": stats["empty"],
        "too_large": stats["too_large"],
        "timeout": stats["timeout"],
        "error": stats["error"],
        "bytes": total_bytes,
        "status_codes": {k.replace("status_", ""): stats[k] for k in status_keys},
    })

    print(f"     {colors.GREEN}💾 meta → {download_dir / 'meta.json'}{colors.RESET}\n")
    return {"js": len(js_todo), "html": len(html_todo),
            "skipped": already_skipped, "error": stats["error"]}


# =========================
# Main
# =========================

def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    force = "--force" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — Download JS/HTML"
          f"{' [Force]' if force else ''}{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_download.py <domain> [--force]")
            print("       python3 watch_download.py --all [--force]")
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

    grand_js = grand_html = grand_skipped = grand_errors = 0
    for prog in programs:
        s = process_program(prog, force=force)
        if s:
            grand_js += s["js"]
            grand_html += s["html"]
            grand_skipped += s["skipped"]
            grand_errors += s["error"]

    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ Download complete{colors.RESET}")
    print(f"{colors.GREEN}   JS     : {grand_js}{colors.RESET}")
    print(f"{colors.GREEN}   HTML   : {grand_html}{colors.RESET}")
    if grand_skipped:
        print(f"{colors.CYAN}   Skipped: {grand_skipped} (already downloaded){colors.RESET}")
    if grand_errors:
        print(f"{colors.YELLOW}   Errors : {grand_errors}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")


if __name__ == "__main__":
    main()