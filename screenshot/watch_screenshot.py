#!/usr/bin/env python3
"""
WatchTower - Screenshot Module
Takes screenshots of HTTP services using Playwright (Chromium).
Saves to: database/<program>/screenshots/

Requires: playwright installed
  pip install playwright && playwright install chromium

Skips hosts that redirect to another host (redirect sources). Only the
final canonical host is screenshotted — this saves time when many
subdomains redirect to the same target.

Scope enforcement:
  - out_of_scope (and legacy "ooscope") is applied when reading URLs.
  - OOS wins over scope.
  - Redirect-source hosts are skipped.
  - Defense in depth: lives-http.json is already filtered at write time.

Usage:
  python3 watch_screenshot.py <domain>
  python3 watch_screenshot.py <domain> --fresh
  python3 watch_screenshot.py --all
  python3 watch_screenshot.py --all --fresh
  python3 watch_screenshot.py --all --force
"""

import sys
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

try:
    from playwright.sync_api import sync_playwright
except ImportError:
    print("❌ Playwright not installed.")
    print("   pip install playwright && playwright install chromium")
    sys.exit(1)


# =========================
# Paths
# =========================

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_DIR = BASE_DIR / "database"


# =========================
# Imports from configs/
# =========================

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from configs.colors import colors
from configs.scope import load_scope_from_path, is_in_scope
from configs.hosts import build_redirect_map, is_canonical


# =========================
# Configuration
# =========================

PAGE_TIMEOUT = 8000
BROWSER_TIMEOUT = 30000
RESTART_BROWSER_EVERY = 50

FRESH_WINDOW_SECONDS = 86400  # 24 hours


# =========================
# Helpers
# =========================

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def is_fresh(ts):
    if not ts or ts == "unknown":
        return False
    try:
        return (datetime.now() - datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")).total_seconds() <= FRESH_WINDOW_SECONDS
    except Exception:
        return False


def get_urls(prog_dir: Path, fresh_only=False) -> list:
    """
    Get in-scope, non-redirect URLs from lives-http.json.
    Returns [(host, url, last_seen), ...].
    """
    lf = prog_dir / "http" / "lives-http.json"
    if not lf.exists():
        return []
    try:
        lives = json.loads(lf.read_text())
    except Exception:
        return []

    scope, oos = load_scope_from_path(prog_dir / "program.json")
    redirect_map = build_redirect_map(prog_dir)

    urls = []
    oos_skipped = 0
    redirect_skipped = 0
    for host, info in lives.items():
        url = info.get("url", "")
        if not url:
            continue
        if (scope or oos) and not is_in_scope(host, scope, oos):
            oos_skipped += 1
            continue
        if not is_canonical(host, redirect_map):
            redirect_skipped += 1
            continue
        if fresh_only and not is_fresh(info.get("last_seen", "")):
            continue
        urls.append((host, url, info.get("last_seen", "")))

    if oos_skipped:
        print(f"     {colors.YELLOW}⏭  {oos_skipped} URL(s) skipped (out of scope){colors.RESET}")
    if redirect_skipped:
        print(f"     {colors.GRAY}⏭  {redirect_skipped} URL(s) skipped (redirect sources){colors.RESET}")

    return urls


def get_all_programs():
    if not DATABASE_DIR.exists():
        return []
    progs = []
    for d in DATABASE_DIR.iterdir():
        if d.is_dir() and (d / "program.json").exists():
            try:
                data = json.loads((d / "program.json").read_text())
                progs.append({"name": data.get("program_name", d.name), "path": d})
            except Exception:
                pass
    return progs


def find_program(domain: str):
    """Find program by scope domain."""
    for d in DATABASE_DIR.iterdir():
        if d.is_dir() and (d / "program.json").exists():
            try:
                data = json.loads((d / "program.json").read_text())
                if domain in data.get("scope", []):
                    return {"name": data.get("program_name", d.name), "path": d}
            except Exception:
                pass
    return None


def safe_screenshot(browser, url: str, output_file: Path) -> bool:
    page = None
    try:
        page = browser.new_page()
        page.set_default_navigation_timeout(PAGE_TIMEOUT)
        page.goto(url, timeout=PAGE_TIMEOUT, wait_until="domcontentloaded")
        page.screenshot(path=str(output_file), full_page=True)
        page.close()
        return True
    except Exception:
        try:
            if page:
                page.close()
        except Exception:
            pass
        return False


def take_screenshots(host_urls: list, output_dir: Path, force: bool = False) -> dict:
    if not host_urls:
        return {"screenshots": 0, "errors": 0, "skipped": 0}

    output_dir.mkdir(parents=True, exist_ok=True)
    stats = {"screenshots": 0, "errors": 0, "skipped": 0}
    total = len(host_urls)

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            timeout=BROWSER_TIMEOUT,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--disable-setuid-sandbox"],
        )

        for i, (host, url, _) in enumerate(host_urls, 1):
            output_file = output_dir / f"{host}.png"

            if output_file.exists() and not force:
                stats["skipped"] += 1
                print(f"     {colors.GRAY}[{i}/{total}] {host} (skipped){colors.RESET}")
                continue

            print(f"     {colors.GRAY}[{i}/{total}] {host}...{colors.RESET}")

            if safe_screenshot(browser, url, output_file):
                stats["screenshots"] += 1
                print(f"     {colors.GREEN}✅ {host}{colors.RESET}")
                continue

            if url.startswith("https://"):
                http_url = url.replace("https://", "http://", 1)
                if safe_screenshot(browser, http_url, output_file):
                    stats["screenshots"] += 1
                    print(f"     {colors.GREEN}✅ {host} (http fallback){colors.RESET}")
                    continue

            stats["errors"] += 1
            print(f"     {colors.YELLOW}⚠️ Failed: {host}{colors.RESET}")

            if i % RESTART_BROWSER_EVERY == 0:
                try:
                    browser.close()
                except Exception:
                    pass
                browser = p.chromium.launch(
                    headless=True,
                    timeout=BROWSER_TIMEOUT,
                    args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu", "--disable-setuid-sandbox"],
                )

        try:
            browser.close()
        except Exception:
            pass

    return stats


# =========================
# Main
# =========================

if __name__ == "__main__":
    args = sys.argv[1:]

    all_mode = "--all" in args
    fresh_only = "--fresh" in args
    force = "--force" in args

    targets = [a for a in args if not a.startswith("--")]
    domain = targets[0] if targets else None

    # ==================== ALL PROGRAMS ====================
    if all_mode:
        mode = "Fresh" if fresh_only else "All"
        print(f"{colors.CYAN}[{now()}] WatchTower — Screenshot ({mode}){' [Force]' if force else ''}{colors.RESET}\n")

        progs = get_all_programs()
        if not progs:
            print(f"{colors.RED}❌ No programs found.{colors.RESET}")
            sys.exit(1)

        total_ss = total_err = 0
        for prog in progs:
            pn, pd = prog["name"], prog["path"]
            urls = get_urls(pd, fresh_only)
            if not urls:
                print(f"{colors.YELLOW}⚠️ No URLs for {pn}{colors.RESET}")
                continue

            ss_dir = pd / "screenshots"
            print(f"{colors.BLUE}📸 {pn} — {len(urls)} URL(s){colors.RESET}")
            st = take_screenshots(urls, ss_dir, force)
            total_ss += st["screenshots"]
            total_err += st["errors"]
            print()

        print(f"{colors.GREEN}{'='*50}{colors.RESET}")
        print(f"{colors.GREEN}✅ Done | Screenshots: {total_ss} | Errors: {total_err}{colors.RESET}")

    # ==================== SINGLE DOMAIN ====================
    elif domain:
        program = find_program(domain)
        if not program:
            print(f"{colors.RED}❌ Domain '{domain}' not found in any program.{colors.RESET}")
            sys.exit(1)

        mode = "Fresh" if fresh_only else "All"
        print(f"{colors.CYAN}[{now()}] Screenshot ({mode}) for {domain}{' [Force]' if force else ''}{colors.RESET}")

        urls = get_urls(program["path"], fresh_only)
        if not urls:
            print(f"{colors.YELLOW}⚠️ No URLs found for {domain}{colors.RESET}")
            sys.exit(0)

        ss_dir = program["path"] / "screenshots"
        print(f"     {colors.CYAN}📋 {len(urls)} URL(s){colors.RESET}\n")

        st = take_screenshots(urls, ss_dir, force)
        print(f"\n{colors.GREEN}✅ Done | Screenshots: {st['screenshots']} | Errors: {st['errors']} | Skipped: {st['skipped']}{colors.RESET}")

    # ==================== NO ARGS ====================
    else:
        print(f"Usage:")
        print(f"  python3 watch_screenshot.py <domain>              # All URLs for domain")
        print(f"  python3 watch_screenshot.py <domain> --fresh      # Only fresh URLs")
        print(f"  python3 watch_screenshot.py <domain> --force      # Retake all")
        print(f"  python3 watch_screenshot.py --all                 # All programs")
        print(f"  python3 watch_screenshot.py --all --fresh         # Fresh across all")
        print(f"  python3 watch_screenshot.py --all --fresh --force # Fresh, retake all")
        print(f"")
        print(f"Requires: playwright")
        print(f"  pip install playwright && playwright install chromium")