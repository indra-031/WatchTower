"""Scope enforcement helpers.

Central place to check if a host is allowed to be processed.
OOS takes priority over scope — if a host matches any out_of_scope
pattern, it is rejected even if it also matches a scope pattern.

Both new ("out_of_scope") and legacy ("ooscope") keys are accepted.
Leading "*." wildcards are stripped from patterns.
"""

import json


def _normalize(s):
    """Lowercase, strip, remove leading '*.' from a scope pattern."""
    return (s or "").strip().lower().lstrip("*.").strip()


def get_scope_lists(program_json):
    """Return (scope, out_of_scope) as normalized lowercase lists."""
    if not isinstance(program_json, dict):
        return [], []

    raw_scope = program_json.get("scope") or []
    raw_oos = (
        program_json.get("out_of_scope")
        or program_json.get("ooscope")
        or []
    )

    scope = [_normalize(s) for s in raw_scope if _normalize(s)]
    oos = [_normalize(s) for s in raw_oos if _normalize(s)]

    return scope, oos


def host_matches(host, pattern):
    """True if host == pattern or host is a subdomain of pattern."""
    if not host or not pattern:
        return False
    h = host.strip().lower().rstrip(".")
    p = pattern.strip().lower().rstrip(".")
    return h == p or h.endswith("." + p)


def is_in_scope(host, scope, out_of_scope):
    """
    Return True iff host should be processed.

    Rules:
      - OOS wins: if host matches any OOS pattern → False
      - If no scope patterns defined → True (no whitelist)
      - Else if host matches any scope pattern → True
      - Else → False
    """
    if not host:
        return False

    for pattern in out_of_scope:
        if host_matches(host, pattern):
            return False

    if not scope:
        return True

    for pattern in scope:
        if host_matches(host, pattern):
            return True

    return False


def filter_hosts(hosts, scope, out_of_scope):
    """Filter an iterable of hosts. Returns a list."""
    return [h for h in hosts if is_in_scope(h, scope, out_of_scope)]


def filter_dict(d, scope, out_of_scope):
    """Filter a dict by its keys (hostnames). Returns a new dict."""
    return {k: v for k, v in d.items() if is_in_scope(k, scope, out_of_scope)}


def load_scope_from_path(program_json_path):
    """Load program.json from path and return (scope, oos)."""
    try:
        with open(program_json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return get_scope_lists(data)
    except Exception:
        return [], []