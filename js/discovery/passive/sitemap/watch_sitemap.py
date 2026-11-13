#!/usr/bin/env python3
"""
WatchTower - JS Discovery : Sitemap (passive)
Fetches /sitemap.xml from each in-scope host, parses <loc> entries,
recursively crawls child sitemap indexes (max depth 3), and filters
results by scope.

Writes:
  database/<program>/js/discovery/passive/sitemap/urls.txt
  database/<program>/js/discovery/passive/sitemap/meta.json

Incremental:
  - per-host cache. Hosts checked within FRESH_HOURS are skipped unless --force.
  - Sitemaps change rarely, so 7-day cache keeps daily runs fast.

Scope enforcement:
  - Only in-scope, alive hosts are queried.
  - Results are filtered to URLs whose hostname is in scope (OOS wins).

Usage:
  python3 watch_sitemap.py <domain>
  python3 watch_sitemap.py <domain> --force
  python3 watch_sitemap.py --all
  python3 watch_sitemap.py --all --force

Requires:
  pip install requests
"""

import sys
import json
import requests
import xml.etree.ElementTree as ET
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

TOOL_NAME = "sitemap"
FRESH_HOURS = 168            # 7 days — sitemaps change rarely
TIMEOUT = 10
MAX_DEPTH = 3
MAX_URLS = 50000
USER_AGENT = "Mozilla/5.0 (compatible; WatchTower-Sitemap/1.0)"


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


def get_hosts(program_dir):
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
    return program_dir / "js" / "discovery" / "passive" / TOOL_NAME


def fetch_xml(url):
    try:
        r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
        if r.status_code == 200 and "xml" in r.headers.get("Content-Type", "").lower():
            return r.text
    except Exception:
        pass
    return None


def parse_sitemap(xml_text):
    urls, children = [], []
    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return urls, children

    ns = ""
    if "}" in root.tag:
        ns = root.tag.split("}")[0] + "}"

    for loc in root.findall(f".//{ns}url/{ns}loc"):
        if loc.text:
            urls.append(loc.text.strip())
    for loc in root.findall(f".//{ns}sitemap/{ns}loc"):
        if loc.text:
            children.append(loc.text.strip())

    return urls, children


def crawl_sitemap(base_url):
    root_url = base_url.rstrip("/") + "/sitemap.xml"
    xml = fetch_xml(root_url)
    if not xml:
        return []

    urls, children = parse_sitemap(xml)
    result = list(urls)

    queue = [(c, 1) for c in children]
    while queue:
        url, depth = queue.pop(0)
        if depth > MAX_DEPTH:
            continue
        child_xml = fetch_xml(url)
        if not child_xml:
            continue
        child_urls, child_children = parse_sitemap(child_xml)
        result.extend(child_urls)
        for c in child_children:
            queue.append((c, depth + 1))
        if len(result) > MAX_URLS:
            break

    return sorted(set(result))


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

    hosts = get_hosts(pd)
    if not hosts:
        print(f"{colors.YELLOW}⚠️ No in-scope HTTP hosts{colors.RESET}\n")
        return {"checked": 0, "skipped": 0, "urls": 0}

    scope, oos = load_scope_from_path(pd / "program.json")

    meta = load_json(meta_file)
    per_host = meta.get("per_host", {}) if isinstance(meta, dict) else {}

    checked = skipped = 0

    for host, url in hosts:
        cached = per_host.get(host)
        if not force and isinstance(cached, dict) and is_fresh(cached.get("last_run", "")):
            skipped += 1
            print(f"     {colors.GRAY}[skip] {host} "
                  f"({'found' if cached.get('found') else 'not found'}){colors.RESET}")
            continue

        print(f"     {colors.CYAN}[run] {host}{colors.RESET}")
        raw = crawl_sitemap(url)
        filtered = filter_urls_by_scope(raw, scope, oos)

        per_host[host] = {
            "last_run": now(),
            "found": bool(raw),
            "raw_count": len(raw),
            "urls_count": len(filtered),
            "urls": filtered[:MAX_URLS],
        }
        checked += 1

        if raw:
            print(f"       {colors.GREEN}✅ sitemap found, {len(filtered)} URL(s) "
                  f"in scope (raw: {len(raw)}){colors.RESET}")
        else:
            print(f"       {colors.GRAY}✗ no sitemap{colors.RESET}")

    all_urls = set()
    for h, info in per_host.items():
        for u in info.get("urls", []):
            all_urls.add(u)
    all_urls_sorted = sorted(all_urls)[:MAX_URLS]

    out_dir.mkdir(parents=True, exist_ok=True)
    urls_file.write_text("\n".join(all_urls_sorted) + ("\n" if all_urls_sorted else ""),
                         encoding="utf-8")

    save_json(meta_file, {
        "tool": TOOL_NAME,
        "program": pn,
        "timestamp": now(),
        "hosts_total": len(hosts),
        "urls_total": len(all_urls_sorted),
        "per_host": per_host,
    })

    print(f"\n     {colors.GREEN}💾 saved → {urls_file} ({len(all_urls_sorted)} URLs){colors.RESET}\n")
    return {"checked": checked, "skipped": skipped, "urls": len(all_urls_sorted)}


# =========================
# Main
# =========================

def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    force = "--force" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — Sitemap Discovery"
          f"{' [Force]' if force else ''}{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_sitemap.py <domain> [--force]")
            print("       python3 watch_sitemap.py --all [--force]")
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

    total_checked = total_skipped = total_urls = 0
    for prog in programs:
        s = process_program(prog, force=force)
        total_checked += s["checked"]
        total_skipped += s["skipped"]
        total_urls += s["urls"]

    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ Sitemap discovery complete{colors.RESET}")
    print(f"{colors.GREEN}   Checked  : {total_checked}{colors.RESET}")
    if total_skipped:
        print(f"{colors.CYAN}   Skipped  : {total_skipped} (cached){colors.RESET}")
    print(f"{colors.GREEN}   URLs     : {total_urls}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")


if __name__ == "__main__":
    main()