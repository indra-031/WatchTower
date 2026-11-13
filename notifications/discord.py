#!/usr/bin/env python3
"""
WatchTower - Discord Notification Module (Diff-based)
Reads database JSON files, compares with last known state,
and sends notifications for new/changed items to Discord.

Config: configs/notifications.json
State:  notification/.last_discord_state.json

Usage:
  python3 discord.py              # Check & notify
  python3 discord.py --demo       # Send demo notifications
  python3 discord.py --reset      # Reset state
  python3 discord.py --test       # Test webhook connection
"""

import json
import sys
import time
import requests
from datetime import datetime
from pathlib import Path


# =========================
# Paths
# =========================

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_DIR = BASE_DIR / "database"
CONFIG_FILE = BASE_DIR / "configs" / "notifications.json"
STATE_FILE = Path(__file__).resolve().parent / ".last_discord_state.json"


# =========================
# Defaults (overridable via config)
# =========================

DEFAULT_TIMEOUT = 15
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF = 2
DEFAULT_RATE_LIMIT = 0.5
MAX_MESSAGE_LENGTH = 1990  # Discord hard limit is 2000


# =========================
# Config
# =========================

def load_config():
    if not CONFIG_FILE.exists():
        return {}
    try:
        return json.loads(CONFIG_FILE.read_text())
    except Exception:
        return {}


def dc_cfg():
    return load_config().get("discord", {})


def notify_cfg():
    return load_config().get("notifications", {})


def enabled():
    return bool(dc_cfg().get("enabled", False))


# =========================
# HTTP session (connection pooling)
# =========================

_session = None


def get_session():
    global _session
    if _session is None:
        _session = requests.Session()
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=10,
            max_retries=0,
        )
        _session.mount("https://", adapter)
        _session.mount("http://", adapter)
    return _session


# =========================
# Rate limiting
# =========================

_last_send_time = 0.0


def _respect_rate_limit():
    global _last_send_time
    interval = float(dc_cfg().get("rate_limit", DEFAULT_RATE_LIMIT))
    if interval <= 0:
        return
    elapsed = time.time() - _last_send_time
    if elapsed < interval:
        time.sleep(interval - elapsed)


def _mark_sent():
    global _last_send_time
    _last_send_time = time.time()


# =========================
# Send with retries and fallbacks
# =========================

def send(text: str, silent: bool = False) -> bool:
    """
    Send message to Discord webhook with:
      - configurable timeout
      - retries with exponential backoff (connection/timeout/5xx)
      - 429 rate-limit handling (respects retry_after)
      - length truncation
      - per-message rate limiting
    """
    if not enabled():
        return False

    cfg = dc_cfg()
    webhook = cfg.get("webhook_url", "")
    if not webhook:
        return False

    timeout = float(cfg.get("timeout", DEFAULT_TIMEOUT))
    retries = max(1, int(cfg.get("retries", DEFAULT_RETRIES)))
    backoff = float(cfg.get("retry_backoff", DEFAULT_BACKOFF))

    if len(text) > MAX_MESSAGE_LENGTH:
        text = text[: MAX_MESSAGE_LENGTH - 3] + "..."

    payload = {"content": text}

    sess = get_session()
    _respect_rate_limit()

    for attempt in range(retries):
        try:
            r = sess.post(webhook, json=payload, timeout=timeout)
        except requests.Timeout:
            if not silent:
                print(f"  ⏰ Discord timeout ({attempt + 1}/{retries})")
            time.sleep(backoff * (2 ** attempt))
            continue
        except requests.ConnectionError:
            if not silent:
                print(f"  ❌ Discord connection error ({attempt + 1}/{retries})")
            time.sleep(backoff * (2 ** attempt))
            continue
        except Exception as e:
            if not silent:
                print(f"  ❌ Discord error: {e}")
            return False

        # Discord returns 200 or 204 on success
        if r.status_code in (200, 204):
            _mark_sent()
            return True

        # Rate limited
        if r.status_code == 429:
            try:
                wait = float(r.json().get("retry_after", 5))
            except Exception:
                wait = 5
            if not silent:
                print(f"  ⚠️ Discord rate limited, waiting {wait:.1f}s")
            time.sleep(wait)
            continue

        # Server errors -> retry
        if 500 <= r.status_code < 600:
            if not silent:
                print(f"  ⚠️ Discord {r.status_code} ({attempt + 1}/{retries})")
            time.sleep(backoff * (2 ** attempt))
            continue

        # 400/401/403/404 -> permanent
        if not silent:
            print(f"  ❌ Discord permanent error: {r.status_code}")
        return False

    if not silent:
        print(f"  ❌ Discord failed after {retries} attempts")
    return False


# =========================
# Helpers
# =========================

def esc(s):
    if not s:
        return ""
    return (str(s)
            .replace("\\", "\\\\")
            .replace("`", "\\`")
            .replace("*", "\\*")
            .replace("_", "\\_")
            .replace("~", "\\~"))


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# =========================
# Notification templates
# =========================

def notify_new_subdomain(program, domain, subdomain, source, ts):
    if not notify_cfg().get("new_subdomain", True):
        return
    send(
        f"🆕 **New Subdomain!**\n\n"
        f"📦 **Program:** `{esc(program)}`\n"
        f"🌐 **Domain:** `{esc(domain)}`\n"
        f"🔗 **Subdomain:** `{esc(subdomain)}`\n"
        f"🏷️ **Source:** {esc(source)}\n"
        f"🕐 **Time:** {esc(ts)}"
    )


def notify_new_live_host(program, domain, host, ips, ts):
    if not notify_cfg().get("new_live_host", True):
        return
    send(
        f"💡 **New Live Host!**\n\n"
        f"📦 **Program:** `{esc(program)}`\n"
        f"🌐 **Domain:** `{esc(domain)}`\n"
        f"🔗 **Host:** `{esc(host)}`\n"
        f"📍 **IPs:** `{esc(', '.join(ips) if ips else 'N/A')}`\n"
        f"🕐 **Time:** {esc(ts)}"
    )


def notify_new_http(program, host, url, status, title, tech, ts):
    if not notify_cfg().get("new_http_service", True):
        return
    tech_str = ", ".join(tech[:5]) if tech else "N/A"
    if tech and len(tech) > 5:
        tech_str += f" +{len(tech) - 5}"
    msg = (
        f"🌐 **New HTTP Service!**\n\n"
        f"📦 **Program:** `{esc(program)}`\n"
        f"🔗 **Host:** `{esc(host)}`\n"
        f"🔗 **URL:** {esc(url)}\n"
        f"📊 **Status:** {esc(status)}\n"
    )
    if title:
        msg += f"📝 **Title:** {esc(title)}\n"
    msg += f"⚙️ **Tech:** {esc(tech_str)}\n🕐 **Time:** {esc(ts)}"
    send(msg)


def notify_status_change(program, host, url, old_status, new_status, title, ts):
    if not notify_cfg().get("status_change", True):
        return

    def se(s):
        c = str(s)
        return ("✅" if c.startswith("2")
                else "↪️" if c.startswith("3")
                else "⚠️" if c.startswith("4")
                else "❌" if c.startswith("5")
                else "❓")

    msg = (
        f"🔄 **Status Changed!**\n\n"
        f"📦 **Program:** `{esc(program)}`\n"
        f"🔗 **Host:** `{esc(host)}`\n"
        f"🌐 **URL:** {esc(url)}\n"
        f"{se(old_status)} **Old:** {esc(old_status)} → {se(new_status)} **New:** {esc(new_status)}\n"
    )
    if title:
        msg += f"📝 **Title:** {esc(title)}\n"
    msg += f"🕐 **Time:** {esc(ts)}"
    send(msg)


def notify_nuclei(program, name, severity, host, matched_at, template, description, ts):
    if not notify_cfg().get("nuclei_finding", True):
        return
    sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}
    emoji = sev_emoji.get(severity.lower(), "⚪")
    msg = (
        f"{emoji} **Nuclei — [{severity.upper()}]**\n\n"
        f"📦 **Program:** `{esc(program)}`\n"
        f"📋 **Name:** {esc(name)}\n"
        f"🔗 **Host:** `{esc(host)}`\n"
        f"🎯 **Matched:** {esc(matched_at)}\n"
        f"📝 **Template:** `{esc(template)}`\n"
    )
    if description:
        desc = description[:300] + ("..." if len(description) > 300 else "")
        msg += f"📄 **Desc:** {esc(desc)}\n"
    msg += f"🕐 **Time:** {esc(ts)}"
    send(msg)


def notify_pipeline_start(program):
    if not notify_cfg().get("pipeline_start", False):
        return
    send(f"🚀 **Pipeline Started**\n\n📦 **Program:** `{esc(program)}`\n🕐 {now()}")


def notify_pipeline_complete(program, stats):
    if not notify_cfg().get("pipeline_complete", True):
        return
    msg = (
        f"✅ **Pipeline Completed!**\n\n"
        f"📦 **Program:** `{esc(program)}`\n\n"
        f"📊 **Stats:**\n"
    )
    for k, v in stats.items():
        msg += f"  • {esc(k)}: {v}\n"
    msg += f"\n🕐 {now()}"
    send(msg)


# =========================
# State management
# =========================

def load_state():
    if not STATE_FILE.exists():
        return {}
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {}


def save_state(state):
    STATE_FILE.write_text(json.dumps(state, indent=2, ensure_ascii=False))


# =========================
# Diff engine
# =========================

def get_programs():
    if not DATABASE_DIR.exists():
        return []
    return sorted([
        d.name for d in DATABASE_DIR.iterdir()
        if d.is_dir() and (d / "program.json").exists()
    ])


def load_json(path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def check_all():
    if not enabled():
        print("⚠️ Discord disabled in configs/notifications.json")
        return

    old_state = load_state()
    new_state = {}
    total_notifications = 0
    stats = {"subdomains": 0, "lives": 0, "http": 0, "nuclei": 0, "new": 0}

    print(f"🔍 Checking for changes at {now()}...\n")

    for prog in get_programs():
        prog_dir = DATABASE_DIR / prog
        old_prog = old_state.get(prog, {})
        new_prog = {}

        # ---- SUBDOMAINS ----
        all_subs = load_json(prog_dir / "enum-output" / "all-subdomains.json")
        new_prog["subs"] = list(all_subs.keys())
        old_subs = set(old_prog.get("subs", []))
        current_subs = set(new_prog["subs"])
        stats["subdomains"] += len(current_subs)

        for sub in current_subs - old_subs:
            info = all_subs.get(sub, {})
            sources = info.get("sources", {})
            domain = list(sources.values())[0].get("domain", "unknown") if sources else "unknown"
            source = list(sources.keys())[0] if sources else "unknown"
            ts = info.get("first_seen", now())
            notify_new_subdomain(prog, domain, sub, source, ts)
            total_notifications += 1
            stats["new"] += 1
            print(f"  🆕 Subdomain: {sub}")

        # ---- LIVE HOSTS ----
        lives = load_json(prog_dir / "dns" / "lives.json")
        new_prog["lives"] = list(lives.keys())
        stats["lives"] += len(new_prog["lives"])

        for host in set(new_prog["lives"]) - set(old_prog.get("lives", [])):
            info = lives.get(host, {})
            notify_new_live_host(
                prog,
                info.get("domain", ""),
                host,
                info.get("ips", []),
                info.get("last_seen", now()),
            )
            total_notifications += 1
            stats["new"] += 1
            print(f"  💡 Live: {host}")

        # ---- HTTP SERVICES ----
        http_data = load_json(prog_dir / "http" / "lives-http.json")
        new_prog["http"] = {h: i.get("status_code", "") for h, i in http_data.items()}
        old_http = old_prog.get("http", {})

        for host, info in http_data.items():
            if host not in old_http:
                notify_new_http(
                    prog,
                    host,
                    info.get("url", ""),
                    info.get("status_code", ""),
                    info.get("title", ""),
                    info.get("tech", []),
                    info.get("last_seen", now()),
                )
                total_notifications += 1
                stats["new"] += 1
                print(f"  🌐 HTTP: {host} → {info.get('status_code', '')}")
            elif old_http[host] != info.get("status_code", ""):
                notify_status_change(
                    prog,
                    host,
                    info.get("url", ""),
                    old_http[host],
                    info.get("status_code", ""),
                    info.get("title", ""),
                    info.get("last_seen", now()),
                )
                total_notifications += 1
                print(f"  🔄 Status: {host} {old_http[host]} → {info.get('status_code', '')}")

        stats["http"] += len(http_data)

        # ---- NUCLEI ----
        nuclei_data = load_json(prog_dir / "nuclei" / "lives-nuclei.json")
        new_prog["nuclei"] = list(nuclei_data.keys())
        stats["nuclei"] += len(new_prog["nuclei"])

        for key in set(new_prog["nuclei"]) - set(old_prog.get("nuclei", [])):
            info = nuclei_data.get(key, {})
            notify_nuclei(
                prog,
                info.get("name", ""),
                info.get("severity", ""),
                info.get("host", ""),
                info.get("matched_at", ""),
                info.get("template", ""),
                info.get("description", ""),
                info.get("first_seen", now()),
            )
            total_notifications += 1
            stats["new"] += 1
            print(f"  🔍 Nuclei [{info.get('severity', '?').upper()}]: {info.get('name', '')}")

        new_state[prog] = new_prog

    save_state(new_state)

    print(f"\n{'='*50}")
    print(f"✅ Check complete | Notifications: {total_notifications}")
    if stats["new"]:
        print(f"   🆕 New items: {stats['new']}")

    if total_notifications > 0:
        notify_pipeline_complete("all", stats)
    else:
        if notify_cfg().get("pipeline_complete", True):
            send(f"✅ **WatchTower Check**\n\nNo changes detected.\n🕐 {now()}")


# =========================
# Main
# =========================

if __name__ == "__main__":
    if "--reset" in sys.argv:
        if STATE_FILE.exists():
            STATE_FILE.unlink()
            print("✅ State reset.")
        else:
            print("ℹ️ No state file.")

    elif "--demo" in sys.argv:
        print("🏰 WatchTower - Discord Demo\n")
        if not enabled():
            print("❌ Discord disabled in configs/notifications.json")
            sys.exit(1)
        notify_new_subdomain("icollab", "example.com", "api.example.com", "subfinder", now())
        notify_new_live_host("icollab", "example.com", "api.example.com", ["1.2.3.4"], now())
        notify_new_http("icollab", "api.example.com", "https://api.example.com", "200", "API", ["PHP", "Nginx"], now())
        notify_status_change("icollab", "api.example.com", "https://api.example.com", "200", "500", "API", now())
        notify_nuclei("icollab", "Open Redirect", "medium", "api.example.com",
                      "https://api.example.com/redir", "open-redirect", "Open redirect found", now())
        print("\n✅ Demo sent!")

    elif "--test" in sys.argv:
        print("🏰 WatchTower - Discord Test\n")
        ok = send("✅ **WatchTower Test**\n\nConnection successful! 🎉")
        print("✅ Connected!" if ok else "❌ Failed")

    else:
        check_all()