#!/usr/bin/env python3
"""
WatchTower - JS Enumeration (All Programs)
Thin wrapper that runs watch_js_enum.py with --all.
"""

import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))


if __name__ == "__main__":
    sys.argv = [str(SCRIPT_DIR / "watch_js_enum.py"), "--all"] + sys.argv[1:]
    exec(compile(
        (SCRIPT_DIR / "watch_js_enum.py").read_text(encoding="utf-8"),
        str(SCRIPT_DIR / "watch_js_enum.py"),
        "exec",
    ))