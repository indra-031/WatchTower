#!/usr/bin/env python3
"""
WatchTower - JS Enumeration Pipeline

Consolidated JS recon flow. Runs each step by calling the individual
watch_*.py script directly with `<domain>` or `--all`.

By default, subprocess output is suppressed and only a compact summary
is shown at the end. Use `--verbose` to stream subprocess output live
(useful for debugging individual steps).

Pipeline (in dependency order):

  Detection:
    1.  Webpack detection       (per host)
    2.  Source map detection    (per host)

  Discovery:
    3.  GetJS                    (passive, per host)
    4.  GAU                      (passive, per scope)
    5.  Sitemap                  (passive, per host)
    6.  Wayback URLs             (passive, per scope)
    7.  Katana                   (active, per host)
    8.  SubJS                    (aggregator, needs 3-7)
    9.  Merge discovery          (aggregate all discovery sources)
    10. Download                 (js + html files)

  Extraction:
    11-19.  HTML extraction      (9 modules)
    20-27.  JS extraction        (8 modules)
    28-35.  Inline-JS extraction (8 modules)
    36.     xnLinkFinder
    37.     Extraction merge
    38.     URLs with parameters
    39.     Parameter wordlist

Secret scanners are NOT part of this flow — see secret/watch_secret_all.py

Usage:
  python3 watch_js_enum.py <domain>
  python3 watch_js_enum.py <domain> --force
  python3 watch_js_enum.py --all
  python3 watch_js_enum.py --all --force
  python3 watch_js_enum.py --all --only webpack,sourcemap
  python3 watch_js_enum.py --all --skip download
  python3 watch_js_enum.py --all --verbose
"""

import sys
import json
import time
import subprocess
import threading
from datetime import datetime
from pathlib import Path


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
JS_DIR = BASE_DIR / "js"
WL_DIR = BASE_DIR / "wordlist"

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))
from configs.colors import colors


# =========================
# Step registry
# =========================
# (key, display_name, script_path, supports_force, timeout)
STEPS = [
    # --- 1-2: Detection ---
    ("webpack",     "Webpack Detection",     JS_DIR / "web-pack" / "watch_webpack.py",                            True,  600),
    ("sourcemap",   "Source Map Detection",  JS_DIR / "source-map" / "watch_sourcemap.py",                        True,  600),

    # --- 3-6: Passive discovery ---
    ("getjs",       "GetJS",                 JS_DIR / "discovery" / "passive" / "getjs" / "watch_getjs.py",       True, 1800),
    ("gau",         "GAU",                   JS_DIR / "discovery" / "passive" / "gau" / "watch_gau.py",           True, 2400),
    ("sitemap",     "Sitemap",               JS_DIR / "discovery" / "passive" / "sitemap" / "watch_sitemap.py",   True, 1200),
    ("waybackurls", "Wayback URLs",          JS_DIR / "discovery" / "passive" / "waybackurls" / "watch_waybackurls.py", True, 2400),

    # --- 7-8: Active discovery ---
    ("katana",      "Katana",                JS_DIR / "discovery" / "active" / "katana" / "watch_katana.py",      True, 3600),
    ("subjs",       "SubJS",                 JS_DIR / "discovery" / "active" / "subjs" / "watch_subjs.py",        True, 1800),

    # --- 9-10: Merge + download ---
    ("merge-disc",  "Merge Discovery URLs",  JS_DIR / "discovery" / "merge" / "watch_merge.py",                   True,  600),
    ("download",    "Download JS/HTML",      JS_DIR / "download" / "watch_download.py",                           True, 3600),

    # --- 10.5: JS changes tracking ---
    ("js-changes",  "JS Changes",            JS_DIR / "changes" / "watch_js_changes.py",                          False,  300),

    # --- 11-19: HTML extraction ---
    ("ex-html-inline",     "Extract Inline JS",        JS_DIR / "extraction" / "html" / "watch_inline_js.py",        False, 600),
    ("ex-html-comments",   "Extract HTML Comments",    JS_DIR / "extraction" / "html" / "watch_comments_html.py",    False, 300),
    ("ex-html-emails",     "Extract HTML Emails",      JS_DIR / "extraction" / "html" / "watch_emails_html.py",      False, 300),
    ("ex-html-endpoints",  "Extract HTML Endpoints",   JS_DIR / "extraction" / "html" / "watch_endpoints_html.py",   False, 300),
    ("ex-html-fragments",  "Extract HTML Fragments",   JS_DIR / "extraction" / "html" / "watch_fragments_html.py",   False, 300),
    ("ex-html-libraries",  "Extract HTML Libraries",   JS_DIR / "extraction" / "html" / "watch_libraries_html.py",   False, 300),
    ("ex-html-parameters", "Extract HTML Parameters",  JS_DIR / "extraction" / "html" / "watch_parameters_html.py",  False, 300),
    ("ex-html-paths",      "Extract HTML Paths",       JS_DIR / "extraction" / "html" / "watch_paths_html.py",       False, 300),
    ("ex-html-urls",       "Extract HTML URLs",        JS_DIR / "extraction" / "html" / "watch_urls_html.py",        False, 300),

    # --- 20-27: JS extraction ---
    ("ex-js-comments",    "Extract JS Comments",    JS_DIR / "extraction" / "js" / "watch_comments_js.py",    False, 600),
    ("ex-js-emails",      "Extract JS Emails",      JS_DIR / "extraction" / "js" / "watch_emails_js.py",      False, 300),
    ("ex-js-endpoints",   "Extract JS Endpoints",   JS_DIR / "extraction" / "js" / "watch_endpoints_js.py",   False, 600),
    ("ex-js-fragments",   "Extract JS Fragments",   JS_DIR / "extraction" / "js" / "watch_fragments_js.py",   False, 300),
    ("ex-js-libraries",   "Extract JS Libraries",   JS_DIR / "extraction" / "js" / "watch_libraries_js.py",   False, 300),
    ("ex-js-parameters",  "Extract JS Parameters",  JS_DIR / "extraction" / "js" / "watch_parameters_js.py",  False, 600),
    ("ex-js-paths",       "Extract JS Paths",       JS_DIR / "extraction" / "js" / "watch_paths_js.py",       False, 600),
    ("ex-js-urls",        "Extract JS URLs",        JS_DIR / "extraction" / "js" / "watch_urls_js.py",        False, 600),

    # --- 28-35: Inline-JS extraction ---
    ("ex-inline-comments",    "Extract Inline Comments",    JS_DIR / "extraction" / "inline-js" / "watch_comments_inline_js.py",    False, 300),
    ("ex-inline-emails",      "Extract Inline Emails",      JS_DIR / "extraction" / "inline-js" / "watch_emails_inline_js.py",      False, 300),
    ("ex-inline-endpoints",   "Extract Inline Endpoints",   JS_DIR / "extraction" / "inline-js" / "watch_endpoints_inline_js.py",   False, 300),
    ("ex-inline-fragments",   "Extract Inline Fragments",   JS_DIR / "extraction" / "inline-js" / "watch_fragments_inline_js.py",   False, 300),
    ("ex-inline-libraries",   "Extract Inline Libraries",   JS_DIR / "extraction" / "inline-js" / "watch_libraries_inline_js.py",   False, 300),
    ("ex-inline-parameters",  "Extract Inline Parameters",  JS_DIR / "extraction" / "inline-js" / "watch_parameters_inline_js.py",  False, 300),
    ("ex-inline-paths",       "Extract Inline Paths",       JS_DIR / "extraction" / "inline-js" / "watch_paths_inline_js.py",       False, 300),
    ("ex-inline-urls",        "Extract Inline URLs",        JS_DIR / "extraction" / "inline-js" / "watch_urls_inline_js.py",        False, 300),

    # --- 36-40: 3rd-party + post-processing ---
    ("xnlinkfinder",  "xnLinkFinder",       JS_DIR / "extraction" / "xnlinkfinder" / "watch_xnlinkfinder.py",  False, 1800),
    ("ex-merge",      "Extraction Merge",   JS_DIR / "extraction" / "merge" / "watch_extraction_merge.py",    False,  300),
    ("urls-param",    "URLs With Params",   JS_DIR / "extraction" / "merge" / "watch_urls_with_param.py",     False,  300),
    ("content-disc",  "Content Discovery",  JS_DIR / "content-discovery" / "watch_content_discovery.py",     False,  600),
    ("wl-param",      "Parameter Wordlist", WL_DIR / "parameter" / "watch_parameter_wordlist.py",            False,  120),
]


# =========================
# Helpers
# =========================

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _safe_json(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(errors="ignore"))
    except Exception:
        return {}


def _count_text(path: Path) -> int:
    """Count logical items in a text file."""
    if not path.exists():
        return 0
    try:
        lines = [l for l in path.read_text(errors="ignore").splitlines() if l.strip()]
        # Grouped files (comments/fragments) mark sections with `===`
        if any(l.startswith("===") for l in lines):
            return sum(1 for l in lines if not l.startswith("==="))
        return len(lines)
    except Exception:
        return 0


def _count_json_items(path: Path) -> int:
    if not path.exists():
        return 0
    try:
        data = json.loads(path.read_text(errors="ignore"))
        return len(data) if isinstance(data, list) else 0
    except Exception:
        return 0


def _count_file(path: Path) -> int:
    if path.suffix.lower() == ".json":
        return _count_json_items(path)
    return _count_text(path)


# =========================
# Arg parsing
# =========================

def parse_args(args):
    out = {
        "domain": None,
        "all_mode": False,
        "force": False,
        "verbose": False,
        "only": set(),
        "skip": set(),
    }
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--all":
            out["all_mode"] = True
            i += 1
        elif a == "--force":
            out["force"] = True
            i += 1
        elif a == "--verbose":
            out["verbose"] = True
            i += 1
        elif a == "--only" and i + 1 < len(args):
            out["only"] = {x.strip().lower() for x in args[i + 1].split(",") if x.strip()}
            i += 2
        elif a == "--skip" and i + 1 < len(args):
            out["skip"] = {x.strip().lower() for x in args[i + 1].split(",") if x.strip()}
            i += 2
        elif a.startswith("--"):
            i += 1
        else:
            out["domain"] = a.strip().lower().lstrip("*.")
            i += 1

    if not out["all_mode"] and not out["domain"]:
        out["all_mode"] = True

    return out


# =========================
# Step runner
# =========================

def run_step(key, name, script, supports_force, timeout,
             domain, all_mode, force, verbose=False):
    if not script.exists():
        print(f"{colors.RED}❌ Script missing: {script}{colors.RESET}")
        return {"key": key, "name": name, "status": "missing",
                "exit_code": -1, "duration": 0.0}

    cmd = [sys.executable, str(script)]
    if domain and not all_mode:
        cmd.append(domain)
    else:
        cmd.append("--all")
    if force and supports_force:
        cmd.append("--force")

    print(f"{colors.BLUE}▶ {name}{colors.RESET}")
    if verbose:
        print(f"  {colors.GRAY}$ {' '.join(cmd[-3:])}{colors.RESET}")

    start = time.time()
    progress_stop = threading.Event()

    def progress_pinger():
        start_p = time.time()
        while not progress_stop.wait(30):
            elapsed = int(time.time() - start_p)
            print(f"  {colors.GRAY}⏳ {name} ({elapsed}s elapsed){colors.RESET}",
                  flush=True)

    t = threading.Thread(target=progress_pinger, daemon=True)
    t.start()

    try:
        if verbose:
            result = subprocess.run(cmd, timeout=timeout)
            exit_code = result.returncode
        else:
            result = subprocess.run(cmd, capture_output=True, text=True,
                                    timeout=timeout)
            exit_code = result.returncode
            if exit_code != 0:
                # Show last 30 lines for debugging
                out_lines = (result.stdout or "").strip().splitlines()[-30:]
                err_lines = (result.stderr or "").strip().splitlines()[-30:]
                for line in out_lines + err_lines:
                    print(f"  {colors.RED}{line[:200]}{colors.RESET}")
        status = "success" if exit_code == 0 else "failed"
    except subprocess.TimeoutExpired:
        print(f"  {colors.YELLOW}⏰ Timeout after {timeout}s{colors.RESET}")
        exit_code, status = -1, "timeout"
    except Exception as e:
        print(f"  {colors.RED}❌ {e}{colors.RESET}")
        exit_code, status = -1, "error"
    finally:
        progress_stop.set()
        t.join(timeout=1)

    duration = time.time() - start
    icon = "✅" if status == "success" else "⚠️ "
    color = colors.GREEN if status == "success" else colors.YELLOW
    print(f"{color}{icon} {name} ({duration:.1f}s){colors.RESET}\n")

    return {"key": key, "name": name, "status": status,
            "exit_code": exit_code, "duration": duration}


# =========================
# Summary
# =========================

def print_summary(programs):
    print()
    print(f"{colors.GREEN}{'═'*62}{colors.RESET}")
    print(f"{colors.GREEN}  JS ENUMERATION SUMMARY{colors.RESET}")
    print(f"{colors.GREEN}{'═'*62}{colors.RESET}")

    # --- Detection ---
    wp_pos = wp_tot = 0
    sm_pos = sm_tot = 0
    for prog in programs:
        pd = prog["path"]
        wp = _safe_json(pd / "js" / "web-pack" / "detect.json")
        wp_pos += int(wp.get("hosts_with_webpack", 0))
        wp_tot += int(wp.get("hosts_total", 0))
        sm = _safe_json(pd / "js" / "source-map" / "detect.json")
        sm_pos += int(sm.get("hosts_with_source_map", 0))
        sm_tot += int(sm.get("hosts_total", 0))

    print()
    print(f"{colors.CYAN}Detection:{colors.RESET}")
    print(f"  {'webpack':<20}: {wp_pos:>5} / {wp_tot} hosts")
    print(f"  {'source-map':<20}: {sm_pos:>5} / {sm_tot} hosts")

    # --- Discovery ---
    print()
    print(f"{colors.CYAN}Discovery URLs:{colors.RESET}")
    disc_files = [
        ("getjs",       "passive/getjs/urls.txt"),
        ("gau",         "passive/gau/urls.txt"),
        ("sitemap",     "passive/sitemap/urls.txt"),
        ("waybackurls", "passive/waybackurls/urls.txt"),
        ("katana",      "active/katana/urls.txt"),
        ("subjs",       "active/subjs/urls.txt"),
        ("merge",       "merge/urls.txt"),
    ]
    for label, rel in disc_files:
        total = sum(
            _count_file(prog["path"] / "js" / "discovery" / rel)
            for prog in programs
        )
        print(f"  {label:<20}: {total:>5}")

    # --- Download ---
    js_dl = html_dl = 0
    for prog in programs:
        jd = prog["path"] / "js" / "download" / "js"
        hd = prog["path"] / "js" / "download" / "html"
        js_dl += len(list(jd.glob("*.js"))) if jd.exists() else 0
        html_dl += len(list(hd.glob("*.html"))) if hd.exists() else 0

    print()
    print(f"{colors.CYAN}Downloaded files:{colors.RESET}")
    print(f"  {'JS files':<20}: {js_dl:>5}")
    print(f"  {'HTML files':<20}: {html_dl:>5}")

    # --- Extraction ---
    print()
    print(f"{colors.CYAN}Extraction:{colors.RESET}")
    extract_tools = [
        ("comments",   "comments.txt"),
        ("emails",     "emails.txt"),
        ("endpoints",  "endpoints.txt"),
        ("fragments",  "fragments.txt"),
        ("libraries",  "libraries.json"),
        ("parameters", "parameters.txt"),
        ("paths",      "paths.txt"),
        ("urls",       "urls.txt"),
    ]
    for category in ("html", "js", "inline-js"):
        for tool, fname in extract_tools:
            total = sum(
                _count_file(prog["path"] / "js" / "extraction" / category / fname)
                for prog in programs
            )
            print(f"  {category:<10} {tool:<12}: {total:>5}")

    # --- xnLinkFinder ---
    print()
    print(f"{colors.CYAN}xnLinkFinder:{colors.RESET}")
    xn = {"links": 0, "parameters": 0, "secrets": 0,
          "out_of_scope": 0, "wordlist": 0}
    for prog in programs:
        base = prog["path"] / "js" / "extraction" / "xnlinkfinder"
        for k in xn:
            xn[k] += _count_file(base / f"{k}.txt")
    for k, v in xn.items():
        print(f"  {k:<20}: {v:>5}")

    # --- Merge & Post ---
    print()
    print(f"{colors.CYAN}Merge & Post-Processing:{colors.RESET}")
    merged = 0
    urls_param = 0
    for prog in programs:
        merge_dir = prog["path"] / "js" / "extraction" / "merge"
        if merge_dir.exists():
            for f in merge_dir.glob("*-merge.*"):
                merged += _count_file(f)
        urls_param += _count_file(merge_dir / "urls-with-param.txt")
    wl_total = _count_text(WL_DIR / "parameter" / "wordlist-parameter.txt")

    print(f"  {'extraction items':<20}: {merged:>5}")
    print(f"  {'URLs with params':<20}: {urls_param:>5}")
    print(f"  {'parameter wordlist':<20}: {wl_total:>5} (global)")

    print(f"{colors.GREEN}{'═'*62}{colors.RESET}")
    print()

    # --- JS Changes ---
    print()
    print(f"{colors.CYAN}JS Changes:{colors.RESET}")
    js_added = js_changed = js_removed = 0
    for prog in programs:
        meta = _safe_json(prog["path"] / "js" / "changes" / "meta.json")
        js_added += int(meta.get("added", 0))
        js_changed += int(meta.get("changed", 0))
        js_removed += int(meta.get("removed", 0))
    print(f"  {'added':<20}: {js_added:>5}")
    print(f"  {'changed':<20}: {js_changed:>5}")
    print(f"  {'removed':<20}: {js_removed:>5}")

    # --- Content Discovery ---
    print()
    print(f"{colors.CYAN}Content Discovery:{colors.RESET}")
    cd = {"urls": 0, "urls_with_param": 0, "js_urls": 0,
          "html_urls": 0, "paths": 0, "parameters": 0}
    for prog in programs:
        meta = _safe_json(prog["path"] / "content" / "meta.json")
        counts = meta.get("counts", {})
        for k in cd:
            cd[k] += int(counts.get(k, 0))
    print(f"  {'urls':<20}: {cd['urls']:>5}")
    print(f"  {'urls with param':<20}: {cd['urls_with_param']:>5}")
    print(f"  {'js urls':<20}: {cd['js_urls']:>5}")
    print(f"  {'html urls':<20}: {cd['html_urls']:>5}")
    print(f"  {'paths':<20}: {cd['paths']:>5}")
    print(f"  {'parameters':<20}: {cd['parameters']:>5}")

# =========================
# Main
# =========================

def main():
    parsed = parse_args(sys.argv[1:])

    steps = list(STEPS)
    if parsed["only"]:
        steps = [s for s in steps if s[0] in parsed["only"]]
    if parsed["skip"]:
        steps = [s for s in steps if s[0] not in parsed["skip"]]

    if not steps:
        print(f"{colors.RED}❌ No steps to run after filtering.{colors.RESET}")
        sys.exit(1)

    # Resolve program list for summary
    programs = []
    if parsed["all_mode"]:
        for d in sorted(DATABASE_DIR.iterdir()) if DATABASE_DIR.exists() else []:
            if d.is_dir() and not d.name.startswith("_") and (d / "program.json").exists():
                programs.append({"program_name": d.name, "path": d})
    elif parsed["domain"]:
        # Match program dir by scope
        for d in sorted(DATABASE_DIR.iterdir()) if DATABASE_DIR.exists() else []:
            if not d.is_dir() or not (d / "program.json").exists():
                continue
            try:
                data = json.loads((d / "program.json").read_text())
            except Exception:
                continue
            scopes = data.get("scope", []) + data.get("out_of_scope", data.get("ooscope", []))
            for s in scopes:
                clean = s.lstrip("*.").lower()
                if parsed["domain"] == clean or parsed["domain"].endswith("." + clean):
                    programs.append({"program_name": d.name, "path": d})
                    break

    mode = "Force" if parsed["force"] else "Cached"
    target = f"domain={parsed['domain']}" if parsed["domain"] else "--all"
    print(f"{colors.CYAN}[{now()}] WatchTower — JS Enumeration{colors.RESET}")
    print(f"{colors.GRAY}   Target : {target}{colors.RESET}")
    print(f"{colors.GRAY}   Mode   : [{mode}]{colors.RESET}")
    print(f"{colors.GRAY}   Steps  : {len(steps)}/{len(STEPS)}{colors.RESET}")
    if parsed["verbose"]:
        print(f"{colors.GRAY}   Verbose: ON (streaming subprocess output){colors.RESET}")
    print()

    start_ts = time.time()
    results = []
    for key, name, script, supports_force, timeout in steps:
        r = run_step(
            key, name, script, supports_force, timeout,
            domain=parsed["domain"],
            all_mode=parsed["all_mode"],
            force=parsed["force"],
            verbose=parsed["verbose"],
        )
        results.append(r)

    total_duration = time.time() - start_ts
    succeeded = sum(1 for r in results if r["status"] == "success")
    failed = [r for r in results if r["status"] != "success"]

    print(f"{colors.GREEN}╔══════════════════════════════════════════════════════╗{colors.RESET}")
    print(f"{colors.GREEN}║        ✅ JS ENUMERATION COMPLETE                    ║{colors.RESET}")
    print(f"{colors.GREEN}╚══════════════════════════════════════════════════════╝{colors.RESET}")

    print()
    print(f"{colors.GREEN}   Duration : {total_duration:.1f}s{colors.RESET}")
    print(f"{colors.GREEN}   Steps    : {succeeded}/{len(results)} succeeded{colors.RESET}")

    if failed:
        print(f"{colors.YELLOW}   Failed   : {len(failed)}{colors.RESET}")
        for r in failed:
            print(f"     {colors.GRAY}• {r['name']} ({r['status']}){colors.RESET}")

    # Compact summary
    print_summary(programs)

    if succeeded == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()