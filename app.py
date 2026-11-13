#!/usr/bin/env python3
"""
WatchTower - Web UI
Flask-based dashboard for browsing enumeration data.
All data is read from JSON files. No database required.

Data sources per program (under database/<program>/):
  program.json
  enum-output/all-subdomains.json
  dns/lives.json
  http/lives-http.json
  cdn/lives-cdn.json
  vhost/lives-vhost.json
  portscan/lives-portscan.json
  whois/lives-whois.json
  screenshots/*.png
  attack/nuclei/nuclei-result.json

Route contract:
  /                     -> HTML pages (rendered from ui/)
  /api/*                -> JSON only (enforced by after_request guard)

program.json schema (legacy "ooscope" is still accepted):
  {
    "program_name": "example",
    "scope":        ["example.com", "example.org"],
    "out_of_scope": ["x.example.com"],
    "cidr":         ["192.0.2.0/24"],
    "asn":          ["AS15169"],
    "ip":           ["198.51.100.120"]
  }

HTML pages:
  /                     Dashboard
  /programs             Programs
  /subdomains           All subdomains
  /fresh-subdomains     Fresh subdomains (24h)
  /live-subdomains      Live hosts
  /http-assets          All HTTP services
  /fresh-http-assets    Fresh HTTP services (24h)
  /portscan             Port scan results
  /screenshots          Screenshot gallery
  /advanced-search      Multi-filter search
  /cdn                  WAF / CDN detection
  /vhost                Virtual hosts
  /whois                WHOIS / RDAP records
  /bruteforce           Brute-force-only subdomains
  /out-of-scope         Out-of-scope targets per program
  /attack               Attack modules hub
  /attack/nuclei        Nuclei findings
  /bookmark             Bookmarks (LocalStorage)
  /works                Works / journal (LocalStorage)
  /js                   JS analysis (placeholder)
  /help                 Documentation

  Legacy compat redirects:
    /waf                   -> /cdn
    /nuclei                -> /attack/nuclei
    /bruteforce-subdomains -> /bruteforce
    /fresh-live-subdomains -> /live-subdomains

JSON API (all under /api):
  Stats & programs:
    GET /api/stats
    GET /api/programs
    GET /api/program/<name>

  Subdomains:
    GET /api/subdomains                  (aggregate, ?fresh=1)
    GET /api/subdomains/fresh            (aggregate, fresh only)
    GET /api/subdomains/<name>
    GET /api/subdomains/<name>/fresh

  Live hosts:
    GET /api/lives                       (aggregate, ?fresh=1)
    GET /api/lives/<name>
    GET /api/lives/<name>/fresh

  HTTP:
    GET /api/http                        (aggregate, ?fresh=1)
    GET /api/http/<name>
    GET /api/http/<name>/fresh

  Nuclei:
    GET /api/nuclei                      (aggregate)
    GET /api/nuclei/<name>

  Port scan:
    GET /api/portscan                    (aggregate)
    GET /api/portscan/<name>

  WAF/CDN:
    GET /api/cdn                         (aggregate)
    GET /api/cdn/<name>

  Virtual hosts:
    GET /api/vhost                       (aggregate)
    GET /api/vhost/<name>

  WHOIS:
    GET /api/whois                       (aggregate)
    GET /api/whois/<name>

  Brute-only:
    GET /api/bruteforce                  (aggregate)
    GET /api/bruteforce/<name>

  Screenshots:
    GET /api/screenshots                 (aggregate)
    GET /api/screenshots/<name>

  Legacy compat (kept, still JSON):
    GET /api/all-programs
    GET /api/all-subdomains
    GET /api/all-live-subdomains
    GET /api/all-fresh-lives
    GET /api/all-http-assets
    GET /api/fresh-http-assets
"""

from flask import (
    Flask, jsonify, render_template, request, send_file, redirect,
)
from pathlib import Path
from datetime import datetime, timedelta
import json


# =========================
# Paths
# =========================

BASE_DIR = Path(__file__).resolve().parent
DATABASE_DIR = BASE_DIR / "database"
UI_DIR = BASE_DIR / "ui"


# =========================
# App
# =========================

app = Flask(
    __name__,
    template_folder=str(UI_DIR),
    static_folder=str(UI_DIR / "static"),
    static_url_path="/static",
)


# =========================
# Constants
# =========================

FRESH_HOURS = 24

# Subdomain sources that count as "brute-force only".
# Both legacy ("ns_brute_*") and current ("dns_brute_*") labels are recognized
# so older databases continue to work after the DNS module rename.
BRUTE_SOURCES = {
    "ns_brute_static", "ns_brute_dynamic",
    "dns_brute_static", "dns_brute_dynamic",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# =========================
# Data helpers
# =========================

def get_all_programs():
    """Return sorted list of all program directory names."""
    if not DATABASE_DIR.exists():
        return []
    return sorted(
        d.name for d in DATABASE_DIR.iterdir()
        if d.is_dir() and (d / "program.json").exists()
    )


def load_json(path: Path):
    """Safely load a JSON file. Returns {} on any error."""
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def load_program(name):
    return load_json(DATABASE_DIR / name / "program.json")


def load_all_subdomains(name):
    return load_json(DATABASE_DIR / name / "enum-output" / "all-subdomains.json")


def load_lives(name):
    return load_json(DATABASE_DIR / name / "dns" / "lives.json")


def load_lives_http(name):
    return load_json(DATABASE_DIR / name / "http" / "lives-http.json")


def load_lives_cdn(name):
    return load_json(DATABASE_DIR / name / "cdn" / "lives-cdn.json")


def load_vhost(name):
    return load_json(DATABASE_DIR / name / "vhost" / "lives-vhost.json")


def load_portscan(name):
    return load_json(DATABASE_DIR / name / "portscan" / "lives-portscan.json")


def load_whois(name):
    """WHOIS records (keyed by "<type>:<target>")."""
    data = load_json(DATABASE_DIR / name / "whois" / "lives-whois.json")
    return data if isinstance(data, dict) else {}


def load_nuclei(name):
    """Load nuclei-result.json from attack/nuclei/. Returns list."""
    data = load_json(DATABASE_DIR / name / "attack" / "nuclei" / "nuclei-result.json")
    return data if isinstance(data, list) else []

def load_lives_asn(name):
    """ASN → CIDRs mapping. database/<program>/asn/lives-asn.json"""
    data = load_json(DATABASE_DIR / name / "asn" / "lives-asn.json")
    return data if isinstance(data, dict) else {}


def load_lives_cidr(name):
    """CIDR → IPs mapping. database/<program>/cidr/lives-cidr.json"""
    data = load_json(DATABASE_DIR / name / "cidr" / "lives-cidr.json")
    return data if isinstance(data, dict) else {}


def load_lives_ip(name):
    """Single IP enrichment. database/<program>/ip/lives-ip.json"""
    data = load_json(DATABASE_DIR / name / "ip" / "lives-ip.json")
    return data if isinstance(data, dict) else {}


def load_screenshots(name):
    """Return list of screenshot filenames for a program."""
    ss_dir = DATABASE_DIR / name / "screenshots"
    if not ss_dir.exists():
        return []
    return sorted(
        f.name for f in ss_dir.iterdir()
        if f.is_file() and f.suffix.lower() == ".png"
    )


def _count(value):
    """Return len() for dict/list, else 0."""
    if isinstance(value, (dict, list)):
        return len(value)
    return 0


def is_fresh(timestamp_str, hours=FRESH_HOURS):
    """Check whether a timestamp string is within the last N hours."""
    if not timestamp_str or timestamp_str == "unknown":
        return False
    try:
        ts = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        return (datetime.now() - ts) <= timedelta(hours=hours)
    except Exception:
        return False


def wants_fresh():
    """Read the ?fresh=1 query param consistently across aggregate endpoints."""
    return request.args.get("fresh") in ("1", "true", "yes")


def get_source_stats(name):
    """Count subdomains per source for one program."""
    all_subs = load_all_subdomains(name)
    stats = {}
    for _sub, info in all_subs.items():
        for src in info.get("sources", {}):
            stats[src] = stats.get(src, 0) + 1
    return stats


def get_global_stats():
    """Compute global + per-program statistics."""
    programs_list = get_all_programs()
    stats = {
        "programs": len(programs_list),
        "total_subdomains": 0,
        "total_lives": 0,
        "total_http": 0,
        "total_nuclei": 0,
        "total_cdn": 0,
        "total_vhost": 0,
        "total_portscan": 0,
        "total_whois": 0,
    }
    programs_data = []

    for p_name in programs_list:
        prog = load_program(p_name)
        all_subs = load_all_subdomains(p_name)
        lives = load_lives(p_name)
        http = load_lives_http(p_name)
        nuclei = load_nuclei(p_name)
        cdn = load_lives_cdn(p_name)
        vhost = load_vhost(p_name)
        portscan = load_portscan(p_name)
        whois = load_whois(p_name)

        subs_count = _count(all_subs)
        lives_count = _count(lives)
        http_count = _count(http)
        nuclei_count = _count(nuclei)
        cdn_count = _count(cdn)
        vhost_count = _count(vhost)
        portscan_count = _count(portscan)
        whois_count = _count(whois)

        stats["total_subdomains"] += subs_count
        stats["total_lives"] += lives_count
        stats["total_http"] += http_count
        stats["total_nuclei"] += nuclei_count
        stats["total_cdn"] += cdn_count
        stats["total_vhost"] += vhost_count
        stats["total_portscan"] += portscan_count
        stats["total_whois"] += whois_count

        programs_data.append({
            "name": p_name,
            "scopes": prog.get("scope", []),
            "subdomains_count": subs_count,
            "lives_count": lives_count,
            "http_count": http_count,
            "nuclei_count": nuclei_count,
            "cdn_count": cdn_count,
            "vhost_count": vhost_count,
            "portscan_count": portscan_count,
            "whois_count": whois_count,
            "sources": get_source_stats(p_name),
        })

    return stats, programs_data


def _brute_only(all_subs):
    """Return subdomains found ONLY by brute-force sources."""
    out = []
    for sub, info in all_subs.items():
        srcs = set(info.get("sources", {}).keys())
        brute = srcs & BRUTE_SOURCES
        if brute and not (srcs - BRUTE_SOURCES):
            out.append({
                "subdomain": sub,
                "first_seen": info.get("first_seen"),
                "last_seen": info.get("last_seen"),
                "sources": sorted(brute),
                "source_details": info.get("sources", {}),
            })
    out.sort(key=lambda x: x["subdomain"])
    return out


def _normalize_nuclei_findings(findings_list, program_name):
    out = []
    for f in findings_list:
        info = f.get("info", {})
        out.append({
            "program": program_name,
            "template": f.get("template-id", f.get("template", "")),
            "name": info.get("name", ""),
            "severity": info.get("severity", ""),
            "host": f.get("host", ""),
            "matched_at": f.get("matched-at", ""),
            "description": info.get("description", ""),
            "tags": info.get("tags", []),
            "timestamp": f.get("timestamp", ""),
        })
    return out


# =========================
# /api Enforcement
# =========================

@app.after_request
def ensure_api_json(response):
    """Safety net: /api/* must never return HTML."""
    if request.path.startswith("/api") and not response.is_json:
        return jsonify({
            "error": "API route returned non-JSON",
            "path": request.path,
            "hint": "All /api/* routes must return JSON, not HTML.",
        }), 500
    return response


@app.before_request
def log_request():
    ip = request.headers.get("X-Forwarded-For", request.remote_addr)
    kind = "API " if request.path.startswith("/api") else "PAGE"
    print(f"🏰 {ip} [{kind}] {request.method} {request.path}")


# =========================
# Error handlers
# =========================

@app.errorhandler(404)
def handle_404(e):
    if request.path.startswith("/api"):
        return jsonify({"error": "not found", "path": request.path}), 404
    return "404 — page not found", 404


@app.errorhandler(500)
def handle_500(e):
    if request.path.startswith("/api"):
        return jsonify({"error": "internal server error"}), 500
    return "500 — internal server error", 500


def _register_exception_handler(flask_app):
    """Only register when debug is off, to avoid clashing with the debugger."""
    @flask_app.errorhandler(Exception)
    def handle_exception(e):
        if request.path.startswith("/api"):
            return jsonify({
                "error": str(e),
                "type": e.__class__.__name__,
            }), 500
        raise e


# ============================================================
# HTML Page Routes
# ============================================================

@app.route("/")
def home():
    stats, programs = get_global_stats()
    return render_template("index.html", stats=stats, programs=programs)


@app.route("/programs")
def page_programs():
    return render_template("programs.html")


@app.route("/subdomains")
def page_subdomains():
    return render_template("subdomains.html")


@app.route("/fresh-subdomains")
def page_fresh_subdomains():
    return render_template("fresh-subdomains.html")


@app.route("/live-subdomains")
def page_live_subdomains():
    return render_template("live-subdomains.html")


@app.route("/http-assets")
def page_http_assets():
    return render_template("http-assets.html")


@app.route("/fresh-http-assets")
def page_fresh_http_assets():
    return render_template("fresh-http-assets.html")


@app.route("/portscan")
def page_portscan():
    return render_template("portscan.html")


@app.route("/screenshots")
def page_screenshots():
    return render_template("screenshots.html")


@app.route("/advanced-search")
def page_advanced_search():
    return render_template("advanced-search.html")


@app.route("/cdn")
def page_cdn():
    return render_template("cdn.html")


@app.route("/vhost")
def page_vhost():
    return render_template("vhost.html")


@app.route("/whois")
def page_whois():
    return render_template("whois.html")

@app.route("/asn")
def page_asn():
    return render_template("asn.html")


@app.route("/cidr")
def page_cidr():
    return render_template("cidr.html")


@app.route("/ip")
def page_ip():
    return render_template("ip.html")


@app.route("/bruteforce")
def page_bruteforce():
    return render_template("bruteforce.html")


@app.route("/out-of-scope")
def page_out_of_scope():
    # Template is stored as out_of_scope.html (underscore in filename).
    return render_template("out_of_scope.html")


@app.route("/bookmark")
def page_bookmark():
    return render_template("bookmark.html")


@app.route("/works")
def page_works():
    return render_template("works.html")


@app.route("/js")
def page_js():
    return render_template("js.html")


@app.route("/help")
def page_help():
    return render_template("help.html")


# ---- Attack module pages ----

@app.route("/attack")
def page_attack():
    return render_template("attack.html")


@app.route("/attack/nuclei")
def page_attack_nuclei():
    return render_template("attack/nuclei.html")


# ---- Deprecated page URLs (folded into other pages) ----

@app.route("/waf")
def page_waf_compat():
    return redirect("/cdn")


@app.route("/nuclei")
def page_nuclei_compat():
    return redirect("/attack/nuclei")


@app.route("/bruteforce-subdomains")
def page_brute_compat():
    return redirect("/bruteforce")


@app.route("/fresh-live-subdomains")
def page_fresh_live_compat():
    return redirect("/live-subdomains")


@app.route("/screenshots/<program>/<filename>")
def serve_screenshot(program, filename):
    ss_path = DATABASE_DIR / program / "screenshots" / filename
    if ss_path.exists() and ss_path.is_file():
        return send_file(str(ss_path))
    return "Screenshot not found", 404


# ============================================================
# JSON API Routes
# ============================================================

# ---------- Stats & Programs ----------

@app.route("/api/stats")
def api_stats():
    stats, _ = get_global_stats()
    detail = {}
    for p_name in get_all_programs():
        cdn = load_lives_cdn(p_name)
        detail[p_name] = {
            "subdomains": _count(load_all_subdomains(p_name)),
            "lives": _count(load_lives(p_name)),
            "http": _count(load_lives_http(p_name)),
            "nuclei": _count(load_nuclei(p_name)),
            "cdn": _count(cdn),
            "waf": _count(cdn),  # alias for older JS
            "vhost": _count(load_vhost(p_name)),
            "portscan": _count(load_portscan(p_name)),
            "whois": _count(load_whois(p_name)),
            "bruteforce": len(_brute_only(load_all_subdomains(p_name))),
            "sources": get_source_stats(p_name),
        }
    stats["programs_detail"] = detail
    return jsonify(stats)


@app.route("/api/programs")
def api_programs():
    out = {}
    for p_name in get_all_programs():
        prog = load_program(p_name)
        out[p_name] = {
            "scopes": prog.get("scope", []),
            "out_of_scope": prog.get(
                "out_of_scope", prog.get("ooscope", [])
            ),
            "cidr": prog.get("cidr", []),
            "asn": prog.get("asn", []),
            "ip": prog.get("ip", []),
        }
    return jsonify(out)


@app.route("/api/program/<program_name>")
def api_program(program_name):
    prog = load_program(program_name)
    if not prog:
        return jsonify({"error": "program not found"}), 404

    return jsonify({
        "program_name": program_name,
        "scopes": prog.get("scope", []),
        "out_of_scope": prog.get(
            "out_of_scope", prog.get("ooscope", [])
        ),
        "cidr": prog.get("cidr", []),
        "asn": prog.get("asn", []),
        "ip": prog.get("ip", []),
        "subdomains_count": _count(load_all_subdomains(program_name)),
        "lives_count": _count(load_lives(program_name)),
        "http_count": _count(load_lives_http(program_name)),
        "nuclei_count": _count(load_nuclei(program_name)),
        "cdn_count": _count(load_lives_cdn(program_name)),
        "vhost_count": _count(load_vhost(program_name)),
        "portscan_count": _count(load_portscan(program_name)),
        "whois_count": _count(load_whois(program_name)),
        "sources": get_source_stats(program_name),
    })


# ---------- Subdomains ----------

@app.route("/api/subdomains")
def api_subdomains_all():
    fresh = wants_fresh()
    out = []
    for p_name in get_all_programs():
        all_subs = load_all_subdomains(p_name)
        for sub, info in all_subs.items():
            if fresh and not is_fresh(info.get("first_seen", "")):
                continue
            out.append({
                "program": p_name,
                "subdomain": sub,
                "first_seen": info.get("first_seen"),
                "last_seen": info.get("last_seen"),
                "sources": list(info.get("sources", {}).keys()),
                "source_details": info.get("sources", {}),
            })
    out.sort(key=lambda x: x["subdomain"])
    return jsonify({"count": len(out), "subdomains": out})


@app.route("/api/subdomains/fresh")
def api_subdomains_fresh_all():
    out = []
    for p_name in get_all_programs():
        all_subs = load_all_subdomains(p_name)
        for sub, info in all_subs.items():
            if is_fresh(info.get("first_seen", "")):
                out.append({
                    "program": p_name,
                    "subdomain": sub,
                    "first_seen": info.get("first_seen"),
                    "sources": list(info.get("sources", {}).keys()),
                    "source_details": info.get("sources", {}),
                })
    out.sort(key=lambda x: x["subdomain"])
    return jsonify({"count": len(out), "fresh_subdomains": out})


@app.route("/api/subdomains/<program_name>")
def api_subdomains(program_name):
    all_subs = load_all_subdomains(program_name)
    out = []
    for sub, info in all_subs.items():
        out.append({
            "subdomain": sub,
            "first_seen": info.get("first_seen"),
            "last_seen": info.get("last_seen"),
            "sources": list(info.get("sources", {}).keys()),
            "source_details": info.get("sources", {}),
        })
    out.sort(key=lambda x: x["subdomain"])
    return jsonify({"program": program_name, "count": len(out), "subdomains": out})


@app.route("/api/subdomains/<program_name>/fresh")
def api_subdomains_fresh(program_name):
    all_subs = load_all_subdomains(program_name)
    out = []
    for sub, info in all_subs.items():
        if is_fresh(info.get("first_seen", "")):
            out.append({
                "subdomain": sub,
                "first_seen": info.get("first_seen"),
                "sources": list(info.get("sources", {}).keys()),
            })
    out.sort(key=lambda x: x["subdomain"])
    return jsonify({"program": program_name, "count": len(out), "fresh_subdomains": out})


# ---------- Live Hosts ----------

@app.route("/api/lives")
def api_lives_all():
    fresh = wants_fresh()
    out = []
    for p_name in get_all_programs():
        for host, info in load_lives(p_name).items():
            if fresh and not is_fresh(info.get("last_seen", "")):
                continue
            out.append({
                "program": p_name,
                "host": host,
                "domain": info.get("domain", ""),
                "ips": info.get("ips", []),
                "last_seen": info.get("last_seen", ""),
            })
    out.sort(key=lambda x: x["host"])
    return jsonify({"count": len(out), "lives": out})


@app.route("/api/lives/<program_name>")
def api_lives(program_name):
    lives = load_lives(program_name)
    out = [{
        "host": h,
        "domain": i.get("domain", ""),
        "ips": i.get("ips", []),
        "last_seen": i.get("last_seen", ""),
    } for h, i in lives.items()]
    out.sort(key=lambda x: x["host"])
    return jsonify({"program": program_name, "count": len(out), "lives": out})


@app.route("/api/lives/<program_name>/fresh")
def api_lives_fresh(program_name):
    lives = load_lives(program_name)
    out = []
    for h, i in lives.items():
        if is_fresh(i.get("last_seen", "")):
            out.append({
                "host": h,
                "domain": i.get("domain", ""),
                "ips": i.get("ips", []),
                "last_seen": i.get("last_seen", ""),
            })
    out.sort(key=lambda x: x["host"])
    return jsonify({"program": program_name, "count": len(out), "lives": out})


# ---------- HTTP Services ----------

@app.route("/api/http")
def api_http_all():
    fresh = wants_fresh()
    out = []
    for p_name in get_all_programs():
        for host, info in load_lives_http(p_name).items():
            if fresh and not is_fresh(info.get("last_seen", "")):
                continue
            out.append({
                "program": p_name,
                "host": host,
                "url": info.get("url", ""),
                "status_code": info.get("status_code", ""),
                "title": info.get("title", ""),
                "tech": info.get("tech", []),
                "ips": info.get("ips", []),
                "webserver": info.get("webserver", ""),
                "last_seen": info.get("last_seen", ""),
            })
    out.sort(key=lambda x: x["host"])
    return jsonify({"count": len(out), "http_services": out})


@app.route("/api/http/<program_name>")
def api_http(program_name):
    http_data = load_lives_http(program_name)
    out = [{
        "host": h,
        "url": i.get("url", ""),
        "status_code": i.get("status_code", ""),
        "title": i.get("title", ""),
        "tech": i.get("tech", []),
        "ips": i.get("ips", []),
        "webserver": i.get("webserver", ""),
        "last_seen": i.get("last_seen", ""),
    } for h, i in http_data.items()]
    out.sort(key=lambda x: x["host"])
    return jsonify({"program": program_name, "count": len(out), "http_services": out})


@app.route("/api/http/<program_name>/fresh")
def api_http_fresh(program_name):
    http_data = load_lives_http(program_name)
    out = []
    for h, i in http_data.items():
        if is_fresh(i.get("last_seen", "")):
            out.append({
                "host": h,
                "url": i.get("url", ""),
                "status_code": i.get("status_code", ""),
                "title": i.get("title", ""),
                "last_seen": i.get("last_seen", ""),
            })
    out.sort(key=lambda x: x["host"])
    return jsonify({"program": program_name, "count": len(out), "http_services": out})


# ---------- Nuclei ----------

@app.route("/api/nuclei")
def api_nuclei_all():
    all_findings = []
    for p_name in get_all_programs():
        all_findings.extend(_normalize_nuclei_findings(load_nuclei(p_name), p_name))

    all_findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"].lower(), 5))
    return jsonify({"count": len(all_findings), "findings": all_findings})


@app.route("/api/nuclei/<program_name>")
def api_nuclei(program_name):
    findings = _normalize_nuclei_findings(load_nuclei(program_name), program_name)
    findings.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"].lower(), 5))
    return jsonify({"program": program_name, "count": len(findings), "findings": findings})


# ---------- Port Scan ----------

@app.route("/api/portscan")
def api_portscan_all():
    results = {}
    total = 0
    for p_name in get_all_programs():
        lives = load_portscan(p_name)
        hosts = [{
            "host": h,
            "domain": i.get("domain", ""),
            "ports": i.get("ports", []),
            "last_seen": i.get("last_seen", ""),
        } for h, i in lives.items()]
        hosts.sort(key=lambda x: x["host"])
        if hosts:
            results[p_name] = hosts
            total += len(hosts)
    return jsonify({"count": total, "programs": results})


@app.route("/api/portscan/<program_name>")
def api_portscan(program_name):
    lives = load_portscan(program_name)
    hosts = [{
        "host": h,
        "domain": i.get("domain", ""),
        "ports": i.get("ports", []),
        "last_seen": i.get("last_seen", ""),
    } for h, i in lives.items()]
    hosts.sort(key=lambda x: x["host"])
    return jsonify({"program": program_name, "count": len(hosts), "hosts": hosts})


# ---------- WAF / CDN ----------

@app.route("/api/cdn")
def api_cdn_all():
    results = {}
    total = 0
    for p_name in get_all_programs():
        cdn = load_lives_cdn(p_name)
        if not cdn:
            continue
        results[p_name] = cdn
        total += _count(cdn)
    return jsonify({"count": total, "programs": results})


@app.route("/api/cdn/<program_name>")
def api_cdn(program_name):
    cdn = load_lives_cdn(program_name)
    return jsonify({"program": program_name, "count": _count(cdn), "hosts": cdn})


# ---------- Virtual Hosts ----------

@app.route("/api/vhost")
def api_vhost_all():
    results = {}
    total = 0
    for p_name in get_all_programs():
        v = load_vhost(p_name)
        if not v:
            continue
        results[p_name] = v
        total += _count(v)
    return jsonify({"count": total, "programs": results})


@app.route("/api/vhost/<program_name>")
def api_vhost(program_name):
    v = load_vhost(program_name)
    return jsonify({"program": program_name, "count": _count(v), "vhosts": v})


# ---------- WHOIS ----------

@app.route("/api/whois")
def api_whois_all():
    results = {}
    total = 0
    for p_name in get_all_programs():
        w = load_whois(p_name)
        if not w:
            continue
        results[p_name] = w
        total += _count(w)
    return jsonify({"count": total, "programs": results})


@app.route("/api/whois/<program_name>")
def api_whois(program_name):
    w = load_whois(program_name)
    return jsonify({"program": program_name, "count": _count(w), "whois": w})


# ---------- ASN ----------

@app.route("/api/asn")
def api_asn_all():
    results = {}
    total = 0
    for p_name in get_all_programs():
        data = load_lives_asn(p_name)
        if not data:
            continue
        results[p_name] = data
        total += _count(data)
    return jsonify({"count": total, "programs": results})


@app.route("/api/asn/<program_name>")
def api_asn(program_name):
    data = load_lives_asn(program_name)
    return jsonify({"program": program_name, "count": _count(data), "asns": data})


# ---------- CIDR ----------

@app.route("/api/cidr")
def api_cidr_all():
    results = {}
    total = 0
    for p_name in get_all_programs():
        data = load_lives_cidr(p_name)
        if not data:
            continue
        results[p_name] = data
        total += _count(data)
    return jsonify({"count": total, "programs": results})


@app.route("/api/cidr/<program_name>")
def api_cidr(program_name):
    data = load_lives_cidr(program_name)
    return jsonify({"program": program_name, "count": _count(data), "cidrs": data})


# ---------- IP ----------

@app.route("/api/ip")
def api_ip_all():
    results = {}
    total = 0
    for p_name in get_all_programs():
        data = load_lives_ip(p_name)
        if not data:
            continue
        results[p_name] = data
        total += _count(data)
    return jsonify({"count": total, "programs": results})


@app.route("/api/ip/<program_name>")
def api_ip(program_name):
    data = load_lives_ip(program_name)
    return jsonify({"program": program_name, "count": _count(data), "ips": data})

# ---------- Brute-only Subdomains ----------

@app.route("/api/bruteforce")
def api_bruteforce_all():
    results = {}
    total = 0
    for p_name in get_all_programs():
        items = _brute_only(load_all_subdomains(p_name))
        if items:
            results[p_name] = items
            total += len(items)
    return jsonify({"count": total, "programs": results})


@app.route("/api/bruteforce/<program_name>")
def api_bruteforce(program_name):
    items = _brute_only(load_all_subdomains(program_name))
    return jsonify({"program": program_name, "count": len(items), "items": items})


# ---------- Screenshots ----------

@app.route("/api/screenshots")
def api_screenshots_all():
    results = {}
    total = 0
    for p_name in get_all_programs():
        files = load_screenshots(p_name)
        if files:
            results[p_name] = files
            total += len(files)
    return jsonify({"count": total, "programs": results})


@app.route("/api/screenshots/<program_name>")
def api_screenshots(program_name):
    files = load_screenshots(program_name)
    return jsonify({"program": program_name, "count": len(files), "files": files})


# ---------- Legacy compatibility (all return JSON) ----------

def _legacy_lives_fresh_payload():
    out = []
    for p_name in get_all_programs():
        for host, info in load_lives(p_name).items():
            if is_fresh(info.get("last_seen", "")):
                out.append({
                    "program": p_name,
                    "host": host,
                    "domain": info.get("domain", ""),
                    "ips": info.get("ips", []),
                    "last_seen": info.get("last_seen", ""),
                })
    out.sort(key=lambda x: x["host"])
    return {"count": len(out), "lives": out}


def _legacy_http_fresh_payload():
    out = []
    for p_name in get_all_programs():
        for host, info in load_lives_http(p_name).items():
            if is_fresh(info.get("last_seen", "")):
                out.append({
                    "program": p_name,
                    "host": host,
                    "url": info.get("url", ""),
                    "status_code": info.get("status_code", ""),
                    "title": info.get("title", ""),
                    "tech": info.get("tech", []),
                    "last_seen": info.get("last_seen", ""),
                })
    out.sort(key=lambda x: x["host"])
    return {"count": len(out), "http_services": out}


@app.route("/api/all-programs")
def legacy_all_programs():
    return api_programs()


@app.route("/api/all-subdomains")
def legacy_all_subdomains():
    return api_subdomains_all()


@app.route("/api/all-live-subdomains")
def legacy_all_lives():
    return api_lives_all()


@app.route("/api/all-fresh-lives")
def legacy_all_fresh_lives():
    return jsonify(_legacy_lives_fresh_payload())


@app.route("/api/all-http-assets")
def legacy_all_http():
    return api_http_all()


@app.route("/api/fresh-http-assets")
def legacy_fresh_http():
    return jsonify(_legacy_http_fresh_payload())


# =========================
# Main
# =========================

if __name__ == "__main__":
    debug = True

    print("🏰 WatchTower Web UI starting...")
    print(f"   UI Files:  {UI_DIR}")
    print(f"   Database:  {DATABASE_DIR}")
    print(f"   URL:       http://0.0.0.0:5000")
    print()

    if not debug:
        _register_exception_handler(app)

    app.run(host="0.0.0.0", port=5000, debug=debug)