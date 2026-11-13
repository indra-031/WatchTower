#!/usr/bin/env python3
"""
WatchTower - Extraction : xnLinkFinder

Runs xnLinkFinder against downloaded JS/HTML/inline-JS directories to
extract links, parameters, secrets, out-of-scope URLs, and wordlist
candidates.

Each source directory is scanned into a per-source temp folder, then
all outputs are concatenated + deduplicated into the final files. This
fixes the "last directory wins" behavior of the original vajra.sh
(which used a single overwriting -o target per run).

Writes:
  database/<program>/js/extraction/xnlinkfinder/links.txt
  database/<program>/js/extraction/xnlinkfinder/parameters.txt
  database/<program>/js/extraction/xnlinkfinder/secrets.txt
  database/<program>/js/extraction/xnlinkfinder/out_of_scope.txt
  database/<program>/js/extraction/xnlinkfinder/wordlist.txt

Usage:
  python3 watch_xnlinkfinder.py <domain>
  python3 watch_xnlinkfinder.py --all

Requires:
  pip install xnLinkFinder

Config (optional, if present):
  js/vajra/configs/xnLinkFinder/config.yml
  configs/xnLinkFinder/config.yml
"""

import sys
import shutil
import subprocess
import tempfile
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


TOOL_NAME = "xnlinkfinder"
OUTPUT_FILES = ["links.txt", "parameters.txt", "secrets.txt",
                "out_of_scope.txt", "wordlist.txt"]
SOURCE_DIRS = [
    ("download/js",         "JS"),
    ("download/inline-js",  "Inline JS"),
    ("download/html",       "HTML"),
]


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize(name):
    return (name.strip().lower()
            .replace(" ", "-").replace("/", "-")
            .replace("\\", "-").replace(":", "-"))


def find_program_by_scope(scope_name):
    import json
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
    import json
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


def find_config():
    for p in [
        BASE_DIR / "js" / "vajra" / "configs" / "xnLinkFinder" / "config.yml",
        BASE_DIR / "configs" / "xnLinkFinder" / "config.yml",
    ]:
        if p.exists():
            return str(p)
    return None


def command_exists(cmd):
    return shutil.which(cmd) is not None


def run_xnlinkfinder_dir(input_dir, out_dir, config_file):
    """Run xnLinkFinder on one directory, writing 5 files into out_dir."""
    cmd = [
        "xnLinkFinder",
        "-i", str(input_dir),
        "-o",  str(out_dir / "links.txt"),
        "-op", str(out_dir / "parameters.txt"),
        "-os", str(out_dir / "secrets.txt"),
        "-oo", str(out_dir / "out_of_scope.txt"),
        "-owl", str(out_dir / "wordlist.txt"),
        "-nb",
    ]
    if config_file:
        cmd += ["--config", config_file]

    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL,
                       stderr=subprocess.DEVNULL, timeout=1200)
    except subprocess.TimeoutExpired:
        print(f"       {colors.YELLOW}⏰ timeout{colors.RESET}")
    except Exception:
        pass


def read_lines(path):
    if not path.exists():
        return []
    try:
        return [l.strip() for l in path.read_text(errors="ignore").splitlines() if l.strip()]
    except Exception:
        return []


def merge_into_final(per_source_outputs, out_dir):
    """Concatenate + dedup all per-source files into final output files."""
    totals = {}
    for filename in OUTPUT_FILES:
        seen = set()
        for src_dir in per_source_outputs:
            for line in read_lines(src_dir / filename):
                seen.add(line)
        sorted_lines = sorted(seen)
        (out_dir / filename).write_text(
            "\n".join(sorted_lines) + ("\n" if sorted_lines else ""),
            encoding="utf-8",
        )
        totals[filename] = len(sorted_lines)
    return totals


def process_program(program):
    pn = program["program_name"]
    pd = program["path"]
    out_dir = pd / "js" / "extraction" / TOOL_NAME
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    # Find any existing source dirs
    existing_sources = []
    for rel, label in SOURCE_DIRS:
        d = pd / "js" / rel
        if d.exists() and any(d.glob("*")):
            existing_sources.append((d, label, rel))

    if not existing_sources:
        print(f"     {colors.YELLOW}⚠️ no download dirs with files{colors.RESET}\n")
        return None

    if not command_exists("xnLinkFinder"):
        print(f"     {colors.RED}❌ xnLinkFinder not installed. "
              f"Install: pip install xnLinkFinder{colors.RESET}\n")
        return None

    config_file = find_config()
    if config_file:
        print(f"     {colors.GRAY}config: {config_file}{colors.RESET}")
    else:
        print(f"     {colors.GRAY}config: (none){colors.RESET}")

    per_source_outputs = []

    for src_dir, label, rel in existing_sources:
        print(f"     {colors.CYAN}[scan] {label} ← {rel}{colors.RESET}")
        tmp_dir = Path(tempfile.mkdtemp(prefix=f"xnlf_{pn}_"))
        try:
            run_xnlinkfinder_dir(src_dir, tmp_dir, config_file)
            per_source_outputs.append(tmp_dir)
        except Exception as e:
            print(f"       {colors.RED}❌ {e}{colors.RESET}")

    if not per_source_outputs:
        print(f"     {colors.YELLOW}no outputs produced{colors.RESET}\n")
        return None

    totals = merge_into_final(per_source_outputs, out_dir)

    # Cleanup tmp
    for t in per_source_outputs:
        shutil.rmtree(t, ignore_errors=True)

    print()
    print(f"     Links      : {totals['links.txt']}")
    print(f"     Parameters : {totals['parameters.txt']}")
    print(f"     Secrets    : {totals['secrets.txt']}")
    print(f"     Out-of-scope: {totals['out_of_scope.txt']}")
    print(f"     {colors.GREEN}💾 saved → {out_dir}{colors.RESET}\n")
    return totals


def main():
    args = sys.argv[1:]
    all_mode = "--all" in args
    non_flags = [a for a in args if not a.startswith("--")]

    print(f"{colors.CYAN}[{now()}] WatchTower — xnLinkFinder{colors.RESET}\n")

    if all_mode:
        programs = get_all_programs()
        if not programs:
            print(f"{colors.RED}❌ No programs found{colors.RESET}")
            sys.exit(1)
    else:
        if not non_flags:
            print("Usage: python3 watch_xnlinkfinder.py <domain>")
            print("       python3 watch_xnlinkfinder.py --all")
            sys.exit(1)
        domain = non_flags[0].strip().lower().lstrip("*.")
        program = find_program_by_scope(domain)
        if not program:
            print(f"{colors.RED}❌ Scope '{domain}' not found{colors.RESET}")
            sys.exit(1)
        pname = program.get("program_name", "unknown")
        programs = [{"program_name": pname, "path": DATABASE_DIR / sanitize(pname)}]

    totals = {"links.txt": 0, "parameters.txt": 0, "secrets.txt": 0}
    for prog in programs:
        r = process_program(prog)
        if r:
            for k in totals:
                totals[k] += r[k]

    print(f"{colors.GREEN}{'='*60}{colors.RESET}")
    print(f"{colors.GREEN}✅ xnLinkFinder complete{colors.RESET}")
    print(f"{colors.GREEN}   Links      : {totals['links.txt']}{colors.RESET}")
    print(f"{colors.GREEN}   Parameters : {totals['parameters.txt']}{colors.RESET}")
    print(f"{colors.GREEN}   Secrets    : {totals['secrets.txt']}{colors.RESET}")
    print(f"{colors.GREEN}{'='*60}{colors.RESET}")


if __name__ == "__main__":
    main()