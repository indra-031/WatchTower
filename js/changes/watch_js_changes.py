#!/usr/bin/env python3
"""
WatchTower - JS Changes

Tracks JS files across pipeline runs by diffing the current contents of
`download/js/` against a previous snapshot. Detects three events:

  - js_added   : a new JS file (new URL) appeared
  - js_changed : an existing JS URL now serves different content
  - js_removed : an existing JS file disappeared from disk

Events are appended to the central change log via configs.changes so the
UI `/changes` page shows them alongside HTTP/DNS events.

State file:  database/<program>/js/changes/js_state.json
Meta file:   database/<program>/js/changes/meta.json

Usage:
  python3 watch_js_changes.py <domain>
  python3 watch_js_changes.py --all
"""

import sys
import json
import hashlib
from datetime import datetime
from pathlib import Path


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
from configs.changes import append_to_program_log


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize(name):
    return (name.strip().lower()
            .replace(" ", "-").replace("/", "-")
            .replace("\\", "-").replace(":", "-"))


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


def load_hash_map(path):
    """Load `<md5> <url>` map → {md5: url}."""
    out = {}
    if not path.exists():
        return out
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            parts = line.strip().split(" ", 1)
            if len(parts) == 2:
                out[parts[0]] = parts[1]
    except Exception:
        pass
    return out


def build_current_snapshot(js_dir, hash_map):
    """
    Return {file_hash: {url, content_hash, size}}.
    file_hash is md5(url) — the filename stem.
    content_hash is md5(file bytes) — changes if the file content changes.
    """
    snap = {}
    if not js_dir.exists():
        return snap
    for f in sorted(js_dir.glob("*.js")):
        try:
            content = f.read_bytes()
        except Exception:
            continue
        snap[f.stem] = {
            "url": hash_map.get(f.stem, ""),
            "content_hash": hashlib.md5(content).hexdigest(),
            "size": len(content),
        }
    return snap


def diff_snapshots(previous, current):
    """Return (added, changed, removed) as sets of file_hash."""
    prev_keys = set(previous.keys())
    cur_keys = set(current.keys())

    added = cur_keys - prev_keys
    removed = prev_keys - cur_keys
    changed = {
        h for h in (cur_keys & prev_keys)
        if current[h]["content_hash"] != previous[h]["content_hash"]
    }
    return added, changed, removed


def emit_changes(program_name, added, changed, removed, current, previous):
    """Build change entries and append to central log."""
    ts = now()
    changes = []

    for h in added:
        info = current[h]
        changes.append({
            "id": f"chg_js_added_{h[:10]}",
            "timestamp": ts,
            "type": "js_added",
            "severity": "low",
            "field": "js_file",
            "old": None,
            "new": info["url"] or h,
            "context": {
                "file_hash": h,
                "content_hash": info["content_hash"],
                "size": info["size"],
            },
        })

    for h in changed:
        cur = current[h]
        prev = previous[h]
        changes.append({
            "id": f"chg_js_changed_{h[:10]}",
            "timestamp": ts,
            "type": "js_changed",
            "severity": "low",
            "field": "js_content",
            "old": prev["content_hash"],
            "new": cur["content_hash"],
            "context": {
                "file_hash": h,
                "url": cur["url"] or prev.get("url", ""),
                "old_size": prev["size"],
                "new_size": cur["size"],
            },
        })

    for h in removed:
        prev = previous[h]
        changes.append({
            "id": f"chg_js_removed_{h[:10]}",
            "timestamp": ts,
            "type": "js_removed",
            "severity": "low",
            "field": "js_file",
            "old": prev["url"] or h,
            "new": None,
            "context": {
                "file_hash": h,
                "content_hash": prev["content_hash"],
                "size": prev["size"],
            },
        })

    if changes:
        for c in changes:
            host = c.get("context", {}).get("url") or c.get("new") or c.get("old") or ""
            append_to_program_log(program_name, host, "js", [c])

    return changes


def process_program(program):
    pn = program["program_name"]
    pd = program["path"]

    js_dir = pd / "js" / "download" / "js"
    hash_map_file = pd / "js" / "download" / "hash-map" / "js-hash-map.txt"
    state_file = pd / "js" / "changes" / "js_state.json"
    meta_file = pd / "js" / "changes" / "meta.json"

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    if not js_dir.exists():
        print(f"     {colors.YELLOW}⚠️ no download/js dir yet{colors.RESET}\n")
        return {"added": 0, "changed": 0, "removed": 0}

    hash_map = load_hash_map(hash_map_file)
    current = build_current_snapshot(js_dir, hash_map)

    previous_meta = load_json(state_file)
    previous = previous_meta.get("files", {}) if isinstance(previous_meta, dict) else {}
    if not isinstance(previous, dict):
        previous = {}

    # First ever run — no previous state. Just save, don't log as "added".
    is_first_run = not previous

    if is_first_run:
        print(f"     {colors.GRAY}first run — saving baseline snapshot "
              f"({len(current)} file(s)){colors.RESET}")
        save_json(state_file, {
            "last_run": now(),
            "files": current,
        })
        save_json(meta_file, {
            "program": pn,
            "timestamp": now(),
            "is_first_run": True,
            "current_total": len(current),
            "added": 0,
            "changed": 0,
            "removed": 0,
        })
        print(f"     {colors.GREEN}💾 baseline → {state_file}{colors.RESET}\n")
        return {"added": 0, "changed": 0, "removed": 0, "first_run": True}

    added, changed, removed = diff_snapshots(previous, current)

    if added or changed or removed:
        emit_changes(pn, added, changed, removed, current, previous)
        print(f"     {colors.GREEN}🆕 added   : {len(added)}{colors.RESET}")
        print(f"     {colors.YELLOW}🔄 changed : {len(changed)}{colors.RESET}")
        print(f"     {colors.RED}💀 removed : {len(removed)}{colors.RESET}")
    else:
        print(f"     {colors.GRAY}no JS changes "
              f"({len(current)} file(s) unchanged){colors.RESET}")

    # Update first_seen / last_seen per file
    ts = now()
    for h, info in current.items():
        prev = previous.get(h, {})
        info["first_seen"] = prev.get("first_seen", ts)
        info["last_seen"] = ts

    save_json(state_file, {
        "last_run": ts,
        "files": current,
    })

    save_json(meta_file, {
        "program": pn,
        "timestamp": ts,
        "is_first_run": False,
        "current_total": len(current),
        "added": len(added),
        "changed": len(changed),
        "removed": len(removed),
    })

    print(f"     {colors.GREEN}💾 state → {state_file}{colors.RESET}\n")
    return {"added": len(added), "changed": len(changed), "removed": len(removed)}


def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — JS Changes{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_js_changes.py <domain>")
            print("       python3 watch_js_changes.py --all")
            sys.exit(1)
        domain = non_flags[0].strip().lower().lstrip("*.")
        program = find_program_by_scope(domain)
        if not program:
            print(f"{colors.RED}❌ Scope '{domain}' not found{colors.RESET}")
            sys.exit(1)
        pname = program.get("program_name", "unknown")
        programs = [{"program_name": pname, "path": DATABASE_DIR / sanitize(pname)}]

    totals = {"added": 0, "changed": 0, "removed": 0}
    for prog in programs:
        r = process_program(prog)
        for k in totals:
            totals[k] += r[k]

    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ JS changes complete{colors.RESET}")
    print(f"{colors.GREEN}   Added   : {totals['added']}{colors.RESET}")
    print(f"{colors.GREEN}   Changed : {totals['changed']}{colors.RESET}")
    print(f"{colors.GREEN}   Removed : {totals['removed']}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")


if __name__ == "__main__":
    main()