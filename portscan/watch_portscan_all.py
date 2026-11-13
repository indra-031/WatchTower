#!/usr/bin/env python3
"""
WatchTower - Port Scan (All Programs)
Thin wrapper that runs watch_portscan.py in --all mode.
Kept separate so orchestration scripts can call it without arguments.
"""

import sys
from pathlib import Path


# =========================
# Imports from local module
# =========================

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))


# =========================
# Main
# =========================

if __name__ == "__main__":
    # Forward CLI flags to the single-file module
    sys.argv = [str(SCRIPT_DIR / "watch_portscan.py"), "--all"] + sys.argv[1:]

    # Execute the single-file module
    exec(
        compile(
            (SCRIPT_DIR / "watch_portscan.py").read_text(encoding="utf-8"),
            str(SCRIPT_DIR / "watch_portscan.py"),
            "exec",
        )
    )