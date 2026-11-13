#!/usr/bin/env python3
"""
WatchTower - Telegram Notification (Sent-tracker)
Checks database for new items, sends to Telegram, tracks what was sent.

Config: configs/telegram-token.json
State:  database/<program>/notification/telegram-sent.json
"""

import json
import sys
import time
import re
import requests
from datetime import datetime
from pathlib import Path


# =========================
# Paths
# =========================

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_DIR = BASE_DIR / "database"
CONFIG_FILE = BASE_DIR / "configs" / "notifications.json"


# =========================
# Defaults (overridable via config)
# =========================

DEFAULT_TIMEOUT = 15         # seconds per request
DEFAULT_RETRIES = 3          # attempts before giving up
DEFAULT_BACKOFF = 2          # base delay for exponential backoff
DEFAULT_RATE_LIMIT = 0.5     # min seconds between messages
MAX_MESSAGE_LENGTH = 4000    # Telegram hard limit is 4096


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


def tg_cfg():
    return load_config().get("telegram", {})


def notify_cfg():
    return load_config().get("notifications", {})


def enabled():
    return bool(tg_cfg().get("enabled", False))


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
            max_retries=0,  # retries handled manually
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
    interval = float(tg_cfg().get("rate_limit", DEFAULT_RATE_LIMIT))
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
    Send a Telegram message with:
      - configurable timeout
      - retries with exponential backoff (connection/timeout/5xx)
      - 429 rate-limit handling (respects retry_after)
      - 400 HTML parse fallback (retries as plain text)
      - length truncation
      - per-message rate limiting
    """
    if not enabled():
        return False

    cfg = tg_cfg()
    token = cfg.get("token", "")
    chat_id = cfg.get("chat_id", "")

    if not token or not chat_id:
        return False

    timeout = float(cfg.get("timeout", DEFAULT_TIMEOUT))
    retries = max(1, int(cfg.get("retries", DEFAULT_RETRIES)))
    backoff = float(cfg.get("retry_backoff", DEFAULT_BACKOFF))

    # Truncate very long messages
    if len(text) > MAX_MESSAGE_LENGTH:
        text = text[: MAX_MESSAGE_LENGTH - 20] + "\n\n…(truncated)"

    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }
    topic = cfg.get("topic_id")
    if topic:
        payload["message_thread_id"] = topic

    sess = get_session()
    _respect_rate_limit()

    for attempt in range(retries):
        try:
            r = sess.post(url, json=payload, timeout=timeout)
        except requests.Timeout:
            if not silent:
                print(f"  ⏰ Telegram timeout ({attempt + 1}/{retries})")
            time.sleep(backoff * (2 ** attempt))
            continue
        except requests.ConnectionError:
            if not silent:
                print(f"  ❌ Telegram connection error ({attempt + 1}/{retries})")
            time.sleep(backoff * (2 ** attempt))
            continue
        except Exception as e:
            if not silent:
                print(f"  ❌ Telegram error: {e}")
            return False

        if r.status_code == 200:
            _mark_sent()
            return True

        # Rate limited
        if r.status_code == 429:
            try:
                wait = r.json().get("parameters", {}).get("retry_after", 5)
            except Exception:
                wait = 5
            if not silent:
                print(f"  ⚠️ Telegram rate limited, waiting {wait}s")
            time.sleep(wait)
            continue

        # HTML parse error -> retry as plain text once
        if r.status_code == 400 and "parse_mode" in payload:
            if not silent:
                print(f"  ⚠️ Telegram 400, retrying as plain text")
            payload.pop("parse_mode", None)
            payload["text"] = re.sub(r"<[^>]+>", "", payload["text"])
            continue

        # Server errors -> retry
        if 500 <= r.status_code < 600:
            if not silent:
                print(f"  ⚠️ Telegram {r.status_code} ({attempt + 1}/{retries})")
            time.sleep(backoff * (2 ** attempt))
            continue

        # Auth / not found -> permanent, don't retry
        if not silent:
            print(f"  ❌ Telegram permanent error: {r.status_code}")
        return False

    if not silent:
        print(f"  ❌ Telegram failed after {retries} attempts")
    return False


# =========================
# Helpers
# =========================

def esc(s):
    if not s:
        return ""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


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


def load_sent(prog: str) -> dict:
    sent_file = DATABASE_DIR / prog / "notification" / "telegram-sent.json"
    if not sent_file.exists():
        return {}
    try:
        return json.loads(sent_file.read_text())
    except Exception:
        return {}


def save_sent(prog: str, data: dict):
    sent_dir = DATABASE_DIR / prog / "notification"
    sent_dir.mkdir(parents=True, exist_ok=True)
    sent_file = sent_dir / "telegram-sent.json"
    sent_file.write_text(json.dumps(data, indent=4, ensure_ascii=False))


# =========================
# Main notify loop
# =========================

def check_and_notify():
    if not enabled():
        print("❌ Telegram disabled in configs/telegram-token.json")
        return

    total_sent = 0
    stats = {"subdomains": 0, "lives": 0, "http": 0, "nuclei": 0, "sent": 0}

    for prog in get_programs():
        pd = DATABASE_DIR / prog
        sent = load_sent(prog)

        # ==================== SUBDOMAINS ====================
        if notify_cfg().get("new_subdomain", True):
            subs = load_json(pd / "enum-output" / "all-subdomains.json")
            sent_subs = set(sent.get("subdomains", []))
            current_subs = set(subs.keys())
            new_subs = current_subs - sent_subs

            for sub in sorted(new_subs):
                info = subs.get(sub, {})
                sources = info.get("sources", {})
                domain = list(sources.values())[0].get("domain", "unknown") if sources else "unknown"
                source = list(sources.keys())[0] if sources else "unknown"

                msg = (
                    f"🆕 <b>New Subdomain!</b>\n\n"
                    f"📦 <b>Program:</b> <code>{esc(prog)}</code>\n"
                    f"🌐 <b>Domain:</b> <code>{esc(domain)}</code>\n"
                    f"🔗 <b>Subdomain:</b> <a href='https://{esc(sub)}'>{esc(sub)}</a>\n"
                    f"🏷️ <b>Source:</b> {esc(source)}\n"
                    f"🕐 <b>Time:</b> {esc(info.get('first_seen', now()))}"
                )

                if send(msg):
                    sent_subs.add(sub)
                    total_sent += 1
                    stats["sent"] += 1
                    print(f"  🆕 {sub}")

            sent["subdomains"] = sorted(sent_subs)
            stats["subdomains"] = len(current_subs)

        # ==================== LIVE HOSTS ====================
        if notify_cfg().get("new_live_host", True):
            lives = load_json(pd / "dns" / "lives.json")
            sent_lives = set(sent.get("lives", []))
            current_lives = set(lives.keys())
            new_lives = current_lives - sent_lives

            for host in sorted(new_lives):
                info = lives.get(host, {})
                ips = ", ".join(info.get("ips", [])[:5]) or "N/A"

                msg = (
                    f"💡 <b>New Live Host!</b>\n\n"
                    f"📦 <b>Program:</b> <code>{esc(prog)}</code>\n"
                    f"🌐 <b>Domain:</b> <code>{esc(info.get('domain', 'unknown'))}</code>\n"
                    f"🔗 <b>Host:</b> <code>{esc(host)}</code>\n"
                    f"📍 <b>IPs:</b> <code>{esc(ips)}</code>\n"
                    f"🕐 <b>Time:</b> {esc(info.get('last_seen', now()))}"
                )

                if send(msg):
                    sent_lives.add(host)
                    total_sent += 1
                    stats["sent"] += 1
                    print(f"  💡 {host}")

            sent["lives"] = sorted(sent_lives)
            stats["lives"] = len(current_lives)

        # ==================== HTTP SERVICES ====================
        if notify_cfg().get("new_http_service", True):
            http_data = load_json(pd / "http" / "lives-http.json")
            sent_http = set(sent.get("http", []))
            current_http = set(http_data.keys())
            new_http = current_http - sent_http

            for host in sorted(new_http):
                info = http_data.get(host, {})
                techs = ", ".join((info.get("tech") or [])[:5]) or "N/A"

                msg = (
                    f"🌐 <b>New HTTP Service!</b>\n\n"
                    f"📦 <b>Program:</b> <code>{esc(prog)}</code>\n"
                    f"🔗 <b>Host:</b> <code>{esc(host)}</code>\n"
                    f"🔗 <b>URL:</b> <a href='{esc(info.get('url', ''))}'>{esc(info.get('url', ''))}</a>\n"
                    f"📊 <b>Status:</b> {esc(str(info.get('status_code', '?')))}\n"
                    f"📝 <b>Title:</b> {esc((info.get('title') or '')[:80])}\n"
                    f"⚙️ <b>Tech:</b> {esc(techs)}\n"
                    f"🕐 <b>Time:</b> {esc(info.get('last_seen', now()))}"
                )

                if send(msg):
                    sent_http.add(host)
                    total_sent += 1
                    stats["sent"] += 1
                    print(f"  🌐 {host}")

            sent["http"] = sorted(sent_http)
            stats["http"] = len(current_http)

        # ==================== STATUS CHANGES ====================
        if notify_cfg().get("status_change", True):
            http_data = load_json(pd / "http" / "lives-http.json")
            sent_status = sent.get("status_changes", {})
            new_status_changes = {}

            for host, info in http_data.items():
                current_status = str(info.get("status_code", ""))
                prev_status = sent_status.get(host, "")

                if prev_status and prev_status != current_status:
                    def se(s):
                        c = str(s)
                        return "✅" if c.startswith("2") else "↪️" if c.startswith("3") else "⚠️" if c.startswith("4") else "❌" if c.startswith("5") else "❓"

                    msg = (
                        f"🔄 <b>Status Changed!</b>\n\n"
                        f"📦 <b>Program:</b> <code>{esc(prog)}</code>\n"
                        f"🔗 <b>Host:</b> <code>{esc(host)}</code>\n"
                        f"🌐 <b>URL:</b> <a href='{esc(info.get('url', ''))}'>{esc(info.get('url', ''))}</a>\n"
                        f"{se(prev_status)} <b>Old:</b> {prev_status} → {se(current_status)} <b>New:</b> {current_status}\n"
                        f"🕐 <b>Time:</b> {esc(info.get('last_seen', now()))}"
                    )

                    if send(msg):
                        total_sent += 1
                        stats["sent"] += 1
                        print(f"  🔄 {host} {prev_status}→{current_status}")

                new_status_changes[host] = current_status

            sent["status_changes"] = new_status_changes

        # ==================== NUCLEI ====================
        if notify_cfg().get("nuclei_finding", True):
            nuclei = load_json(pd / "nuclei" / "lives-nuclei.json")
            sent_nuclei = set(sent.get("nuclei", []))
            current_nuclei = set(nuclei.keys())
            new_nuclei = current_nuclei - sent_nuclei

            for key in sorted(new_nuclei):
                f = nuclei.get(key, {})
                sev = f.get("severity", "info").lower()
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}.get(sev, "⚪")

                msg = (
                    f"{emoji} <b>Nuclei — [{sev.upper()}]</b>\n\n"
                    f"📦 <b>Program:</b> <code>{esc(prog)}</code>\n"
                    f"📋 <b>Name:</b> {esc(f.get('name', '?'))}\n"
                    f"🔗 <b>Host:</b> <code>{esc(f.get('host', ''))}</code>\n"
                    f"🎯 <b>Matched:</b> <a href='{esc(f.get('matched_at', ''))}'>{esc(f.get('matched_at', ''))}</a>\n"
                    f"📝 <b>Template:</b> <code>{esc(f.get('template', ''))}</code>\n"
                    f"🕐 <b>Time:</b> {esc(f.get('first_seen', now()))}"
                )

                if send(msg):
                    sent_nuclei.add(key)
                    total_sent += 1
                    stats["sent"] += 1
                    print(f"  🔍 [{sev.upper()}] {f.get('name', '?')}")

            sent["nuclei"] = sorted(sent_nuclei)
            stats["nuclei"] = len(current_nuclei)

        sent["last_check"] = now()
        save_sent(prog, sent)

    # Summary
    print(f"\n{'='*50}")
    print(f"✅ Check complete | Sent: {total_sent}")
    print(f"   Subdomains: {stats['subdomains']} | Live: {stats['lives']} | HTTP: {stats['http']} | Nuclei: {stats['nuclei']}")

    if total_sent > 0:
        send(
            f"✅ <b>WatchTower Report</b>\n\n"
            f"📊 <b>Stats:</b>\n"
            f"  🌐 Subdomains: {stats['subdomains']}\n"
            f"  💡 Live Hosts: {stats['lives']}\n"
            f"  📡 HTTP: {stats['http']}\n"
            f"  🔍 Nuclei: {stats['nuclei']}\n"
            f"  🆕 New: {stats['sent']}\n"
            f"\n🕐 {now()}"
        )


if __name__ == "__main__":
    if "--reset" in sys.argv:
        for prog in get_programs():
            sent_file = DATABASE_DIR / prog / "notification" / "telegram-sent.json"
            if sent_file.exists():
                sent_file.unlink()
                print(f"  🗑 Reset: {prog}")
        print("✅ All reset. Next run will send everything as new.")
    else:
        check_and_notify()