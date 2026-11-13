"""Canonical host helpers.

httpx records `final_url` per host in `http/lives-http.json`. If a host's
final_url points to a different hostname, we call it a "redirect source"
and downstream expensive modules (katana, download, screenshot, portscan,
nuclei) skip it. The canonical target (if in-scope) is processed once.

This prevents 200 subdomains that all redirect to `example.com` from
being crawled/downloaded/scanned 200 times.
"""

import json
from pathlib import Path
from urllib.parse import urlparse


def _load_json(path):
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def build_redirect_map(program_dir):
    """
    Return {from_host: to_host} based on http/lives-http.json final_url.
    Only hosts whose final_url resolves to a different hostname appear.
    All hostnames are lowercased.
    """
    lives = _load_json(Path(program_dir) / "http" / "lives-http.json")
    out = {}
    for host, info in lives.items():
        final_url = info.get("final_url") or ""
        if not final_url:
            continue
        try:
            final_host = (urlparse(final_url).hostname or "").lower()
        except Exception:
            continue
        if not final_host:
            continue
        h = host.lower()
        if final_host != h:
            out[h] = final_host
    return out


def canonical_host(host, redirect_map):
    """Follow a redirect chain to its canonical host (cycle-safe)."""
    h = (host or "").lower()
    seen = set()
    while h in redirect_map and h not in seen:
        seen.add(h)
        h = redirect_map[h]
    return h


def is_canonical(host, redirect_map):
    """True iff host is NOT a redirect source."""
    return canonical_host(host, redirect_map) == (host or "").lower()


def load_canonical_hosts(program_dir):
    """Set of hosts from lives-http.json that are not redirect sources."""
    lives = _load_json(Path(program_dir) / "http" / "lives-http.json")
    redirect_map = build_redirect_map(program_dir)
    return {h for h in lives if is_canonical(h, redirect_map)}