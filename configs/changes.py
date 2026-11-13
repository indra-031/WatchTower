"""Shared change detection & logging for WatchTower.

Used by all pipeline scripts to:
  - Compare old vs new host state
  - Record changes to database/<program>/changes/changes.json
  - Merge per-host change history into lives-*.json
"""

from pathlib import Path
from datetime import datetime
import json
import random
import string


BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_DIR = BASE_DIR / "database"

# field -> (change_type, severity)
HTTP_CHANGE_RULES = {
    "status_code":    ("status_change",    "critical"),
    "title":          ("title_change",     "high"),
    "hash":           ("content_change",   "medium"),
    "webserver":      ("webserver_change", "medium"),
    "tech":           ("tech_change",      "medium"),
    "a":              ("ip_change",        "high"),
    "content_length": ("length_change",    "low"),
}

MAX_CHANGES_PER_HOST = 50
MAX_CHANGES_PER_PROGRAM = 10000


# =========================
# Helpers
# =========================

def _now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _change_id():
    return "chg_" + "".join(
        random.choices(string.ascii_lowercase + string.digits, k=12)
    )


def _safe_name(n):
    return (n.strip().lower()
            .replace(" ", "-").replace("/", "-")
            .replace("\\", "-").replace(":", "-"))


def _norm(v):
    """Normalize for comparison: lists → sorted strings, strings → stripped."""
    if isinstance(v, list):
        return sorted(str(x) for x in v if x not in (None, ""))
    if isinstance(v, str):
        return v.strip()
    return v


def _has_changed(field, old, new):
    """Field-specific difference test (with noise filters)."""
    o, n = _norm(old), _norm(new)

    if field == "content_length":
        try:
            oi, ni = int(o), int(n)
        except (TypeError, ValueError):
            return False
        if oi == 0:
            return ni > 0
        denom = max(abs(oi), abs(ni))
        return (abs(ni - oi) / denom) > 0.10  # ignore <10% swings

    if field == "tech":
        return set(o or []) != set(n or [])

    return o != n


# =========================
# Detection
# =========================

def detect_http_changes(old_info, new_info, url="", is_behind_cdn=False):
    """
    Compare old vs new host records.
    Returns list of change dicts (empty if nothing meaningful changed).

    IP changes are skipped when the host is behind a CDN, because
    CDN edges rotate constantly and would produce pure noise.
    """
    changes = []
    ts = _now()

    for field, (ctype, severity) in HTTP_CHANGE_RULES.items():
        old_val = old_info.get(field)
        new_val = new_info.get(field)

        # First observation → no comparison possible
        if old_val is None or old_val == "":
            continue

        if field == "a" and is_behind_cdn:
            continue

        if not _has_changed(field, old_val, new_val):
            continue

        changes.append({
            "id": _change_id(),
            "timestamp": ts,
            "type": ctype,
            "severity": severity,
            "field": field,
            "old": old_val,
            "new": new_val,
            "context": {"url": url},
        })

    return changes


# =========================
# Merge into lives-*
# =========================

def merge_host_record(old_info, new_info, changes):
    """
    Merge change history into new_info and set last_changed / first_seen.
    Returns the merged host record (same object).
    """
    ts = _now()

    new_info["first_seen"] = old_info.get("first_seen") or ts
    new_info["last_seen"] = ts

    old_changes = old_info.get("changes")
    if not isinstance(old_changes, list):
        old_changes = []

    merged = old_changes + changes
    if len(merged) > MAX_CHANGES_PER_HOST:
        merged = merged[-MAX_CHANGES_PER_HOST:]
    new_info["changes"] = merged

    if changes:
        new_info["last_changed"] = ts
    else:
        new_info["last_changed"] = (
            old_info.get("last_changed")
            or old_info.get("first_seen")
            or ts
        )

    return new_info


# =========================
# Central log
# =========================

def append_to_program_log(program_name, host, category, changes):
    """Append change entries to database/<program>/changes/changes.json."""
    if not changes:
        return

    log_path = DATABASE_DIR / _safe_name(program_name) / "changes" / "changes.json"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    data = {"changes": []}
    if log_path.exists():
        try:
            loaded = json.loads(log_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict) and isinstance(loaded.get("changes"), list):
                data = loaded
        except Exception:
            data = {"changes": []}

    for ch in changes:
        entry = dict(ch)
        entry["program"] = program_name
        entry["host"] = host
        entry["category"] = category
        data["changes"].append(entry)

    if len(data["changes"]) > MAX_CHANGES_PER_PROGRAM:
        data["changes"] = data["changes"][-MAX_CHANGES_PER_PROGRAM:]

    log_path.write_text(
        json.dumps(data, indent=4, ensure_ascii=False),
        encoding="utf-8",
    )


def load_program_log(program_name):
    """Load changes log for a program. Returns list (or [])."""
    log_path = DATABASE_DIR / _safe_name(program_name) / "changes" / "changes.json"
    if not log_path.exists():
        return []
    try:
        data = json.loads(log_path.read_text(encoding="utf-8"))
        changes = data.get("changes", []) if isinstance(data, dict) else []
        return changes if isinstance(changes, list) else []
    except Exception:
        return []