#!/usr/bin/env python3
"""
WatchTower - Port Scan Module
Scans HTTP hosts with naabu and enriches open ports with service info.

Uses `-sV` (service version detection) which returns structured
"name" and "product" fields in JSON. Falls back to a local port→service
map when naabu does not identify the service.

Strategy:
  - Non-CDN hosts : SYN scan over full DEFAULT_PORTS
  - CDN hosts     : CONNECT scan over CDN-forwarded ports
  - Redirect-source hosts are skipped (canonical host is scanned once)

Scope enforcement:
  - out_of_scope (and legacy "ooscope") is applied to hosts before scan,
    fresh results before save, and existing lives-portscan.json on write.
  - OOS wins over scope.
  - Redirect sources skipped.

Temp host-list files live inside the program's portscan directory
and are removed in `finally`, even on failure.

Reads:
  database/<program>/http/lives-http.json
  database/<program>/cdn/lives-cdn.json
Writes:
  database/<program>/portscan/portscan.json
  database/<program>/portscan/lives-portscan.json
  database/<program>/portscan/fresh-tested-naabu.json   (fresh mode only)

Usage:
  python3 watch_portscan.py <domain>
  python3 watch_portscan.py --all
  python3 watch_portscan.py --all --fresh
  python3 watch_portscan.py --all --fresh --force
"""

import sys
import subprocess
import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path


# =========================
# Paths
# =========================

BASE_DIR = Path(__file__).resolve().parent.parent
DATABASE_DIR = BASE_DIR / "database"


# =========================
# Imports from configs/
# =========================

if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from configs.colors import colors
from configs.scope import load_scope_from_path, is_in_scope
from configs.hosts import build_redirect_map, is_canonical


# =========================
# Configuration
# =========================

DEFAULT_PORTS = (
    "80,443,8080,8443,3000,5000,8000,9000,9090,9443,"
    "3306,5432,6379,27017,22,21,25,53,110,143,993,995"
)

CDN_PORTS = {
    "cloudflare": [80, 8080, 8880, 2052, 2082, 2086, 2095,
                   443, 2053, 2083, 2087, 2096],
    "akamai":     [72, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89,
                   443, 444, 488, 591, 777, 808, 919, 920, 1080],
    "cloudfront": [80, 443] + list(range(1024, 65536)),
    "fastly":     [80, 443],
    "bunny":      [80, 443],
}

CDN_FALLBACK_PORTS = [80, 443]

PORT_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 111: "rpcbind", 135: "msrpc",
    139: "netbios-ssn", 143: "imap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 587: "smtp-submission", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
    2052: "cloudflare-http", 2053: "cloudflare-https",
    2082: "cpanel", 2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl",
    2095: "webmail", 2096: "webmail-ssl", 2375: "docker", 2376: "docker-tls",
    3000: "http-alt", 3306: "mysql", 3389: "rdp", 4444: "metasploit",
    5000: "http-alt", 5432: "postgres", 5601: "kibana", 5900: "vnc",
    5984: "couchdb", 6379: "redis", 6443: "kubernetes-api", 7001: "weblogic",
    8000: "http-alt", 8009: "ajp13", 8080: "http-proxy", 8081: "http-alt",
    8086: "influxdb", 8088: "yarn", 8443: "https-alt", 8880: "http-alt",
    8888: "http-alt", 9000: "http-alt", 9001: "tor-orport", 9042: "cassandra",
    9090: "http-alt", 9092: "kafka", 9100: "jetdirect",
    9200: "elasticsearch", 9300: "elasticsearch-transport", 9443: "https-alt",
    10000: "webmin", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb", 27018: "mongodb", 28017: "mongodb-http",
}


# =========================
# Helpers
# =========================

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sanitize(n):
    return (n.strip().lower()
            .replace(" ", "-").replace("/", "-")
            .replace("\\", "-").replace(":", "-"))


def is_fresh(ts):
    if not ts or ts == "unknown":
        return False
    try:
        return (datetime.now() - datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")) <= timedelta(hours=24)
    except Exception:
        return False


def guess_service(port_str):
    try:
        return PORT_SERVICES.get(int(port_str), "")
    except Exception:
        return ""


def run(cmd, timeout=300):
    print(f"     {colors.GRAY}$ {cmd[:120]}...{colors.RESET}")
    try:
        r = subprocess.run(
            ["bash", "-c", cmd],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if r.returncode != 0:
            err = r.stderr.strip() or f"exit code {r.returncode} (empty stderr)"
            for line in err.splitlines()[-3:]:
                print(f"     {colors.YELLOW}{line[:200]}{colors.RESET}")
        return r.stdout.strip().splitlines() if r.stdout.strip() else []
    except subprocess.TimeoutExpired:
        print(f"     {colors.YELLOW}⏰ Timeout{colors.RESET}")
        return []
    except Exception as e:
        print(f"     {colors.RED}❌ {e}{colors.RESET}")
        return []


def load_cdn_info(prog_dir: Path) -> dict:
    for path in [
        prog_dir / "cdn" / "lives-cdn.json",
        prog_dir / "http" / "lives-waf.json",
    ]:
        if path.exists():
            try:
                return json.loads(path.read_text())
            except Exception:
                continue
    return {}


def get_ports_for_host(host: str, cdn_info: dict) -> str:
    info = cdn_info.get(host, {})
    if not info.get("cdn"):
        return DEFAULT_PORTS
    provider = (info.get("provider") or "").lower().strip()
    for known, ports in CDN_PORTS.items():
        if known in provider:
            return ",".join(str(p) for p in ports)
    print(f"     {colors.YELLOW}⚠️ Unknown CDN provider '{provider}' for {host}, "
          f"using fallback ports {CDN_FALLBACK_PORTS}{colors.RESET}")
    return ",".join(str(p) for p in CDN_FALLBACK_PORTS)


def get_hosts_to_scan(prog_dir: Path, fresh_only=False, force=False) -> tuple:
    lf = prog_dir / "http" / "lives-http.json"
    if not lf.exists():
        return [], {}, 0, {}
    try:
        lives = json.loads(lf.read_text())
    except Exception:
        return [], {}, 0, {}

    cdn_info = load_cdn_info(prog_dir)
    scope, oos = load_scope_from_path(prog_dir / "program.json")
    redirect_map = build_redirect_map(prog_dir)

    ps_dir = prog_dir / "portscan"
    ps_dir.mkdir(parents=True, exist_ok=True)
    tested_file = ps_dir / "fresh-tested-naabu.json"
    tested = json.loads(tested_file.read_text()) if tested_file.exists() else {}

    hosts_to_scan = []
    skipped = 0
    oos_skipped = 0
    redirect_skipped = 0

    for host, info in lives.items():
        url = info.get("url", "")
        if not url:
            continue

        if (scope or oos) and not is_in_scope(host, scope, oos):
            oos_skipped += 1
            continue

        if not is_canonical(host, redirect_map):
            redirect_skipped += 1
            continue

        status = str(info.get("status_code", ""))
        last_seen = info.get("last_seen", "")

        if not fresh_only:
            hosts_to_scan.append(host)
            continue
        if not is_fresh(last_seen):
            continue
        if force:
            hosts_to_scan.append(host)
            continue

        prev = tested.get(host, {})
        if (host not in tested
                or prev.get("status_code", "") != status
                or prev.get("url", "") != url):
            hosts_to_scan.append(host)
        else:
            skipped += 1

    if oos_skipped:
        print(f"     {colors.YELLOW}⏭  {oos_skipped} host(s) skipped (out of scope){colors.RESET}")
    if redirect_skipped:
        print(f"     {colors.GRAY}⏭  {redirect_skipped} host(s) skipped (redirect sources){colors.RESET}")

    return hosts_to_scan, lives, skipped, cdn_info


def mark_as_tested(prog_dir: Path, hosts_scanned: list, lives: dict):
    ps_dir = prog_dir / "portscan"
    ps_dir.mkdir(parents=True, exist_ok=True)
    tested_file = ps_dir / "fresh-tested-naabu.json"
    tested = json.loads(tested_file.read_text()) if tested_file.exists() else {}

    ts = now()
    for host in hosts_scanned:
        info = lives.get(host, {})
        tested[host] = {
            "status_code": str(info.get("status_code", "")),
            "url": info.get("url", ""),
            "last_seen": info.get("last_seen", ""),
            "scanned_at": ts,
        }
    tested_file.write_text(json.dumps(tested, indent=4, ensure_ascii=False))


def get_all_programs():
    if not DATABASE_DIR.exists():
        return []
    progs = []
    for d in DATABASE_DIR.iterdir():
        if d.is_dir() and (d / "program.json").exists():
            try:
                data = json.loads((d / "program.json").read_text())
                progs.append({"name": data.get("program_name", d.name), "path": d})
            except Exception:
                pass
    return progs


# =========================
# naabu wrapper
# =========================

def _scan_batch(hosts: list, ports: str, host_ports: dict, prog_dir: Path, is_cdn: bool):
    if not hosts:
        return

    ps_dir = prog_dir / "portscan"
    ps_dir.mkdir(parents=True, exist_ok=True)

    tmp_file = ps_dir / f".tmp-hosts-{uuid.uuid4().hex[:8]}.txt"
    scan_type = "c" if is_cdn else "s"

    try:
        tmp_file.write_text("\n".join(hosts) + "\n", encoding="utf-8")

        cmd = (
            f"naabu -l {tmp_file} -p {ports} "
            f"-s {scan_type} -sV -silent -json"
        )
        results = run(cmd, timeout=60 + len(hosts) * 30)

        if not results:
            return

        for line in results:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                continue

            host = obj.get("host") or obj.get("ip", "")
            port = obj.get("port")
            if not host or port is None:
                continue

            port_str = str(port)
            name = (obj.get("name") or "").strip()
            product = (obj.get("product") or "").strip()
            tls = bool(obj.get("tls", False))

            if not name:
                name = guess_service(port_str)

            host_ports.setdefault(host, {})[port_str] = {
                "name": name,
                "product": product,
                "tls": tls,
            }

    finally:
        try:
            tmp_file.unlink()
        except Exception:
            pass


def run_portscan(hosts: list, cdn_info: dict, prog_dir: Path) -> dict:
    if not hosts:
        return {}

    non_cdn = [h for h in hosts if not cdn_info.get(h, {}).get("cdn")]
    cdn_hosts = [h for h in hosts if cdn_info.get(h, {}).get("cdn")]

    host_ports = {}

    if non_cdn:
        print(f"     {colors.CYAN}🔌 Scanning {len(non_cdn)} non-CDN host(s) "
              f"with {len(DEFAULT_PORTS.split(','))} port(s) (SYN + -sV)...{colors.RESET}")
        _scan_batch(non_cdn, DEFAULT_PORTS, host_ports, prog_dir, is_cdn=False)

    if cdn_hosts:
        groups = {}
        for h in cdn_hosts:
            ports = get_ports_for_host(h, cdn_info)
            groups.setdefault(ports, []).append(h)

        for ports_str, group_hosts in groups.items():
            provider = (cdn_info.get(group_hosts[0], {}).get("provider") or "CDN")
            print(f"     {colors.CYAN}🔌 Scanning {len(group_hosts)} host(s) behind "
                  f"'{provider}' with {len(ports_str.split(','))} port(s) "
                  f"(CONNECT + -sV)...{colors.RESET}")
            _scan_batch(group_hosts, ports_str, host_ports, prog_dir, is_cdn=True)

    return host_ports


# =========================
# Save
# =========================

def save_results(prog_name: str, domain: str, host_ports: dict):
    sn = sanitize(prog_name)
    ps_dir = DATABASE_DIR / sn / "portscan"
    ps_dir.mkdir(parents=True, exist_ok=True)
    ts = now()

    scope, oos = load_scope_from_path(DATABASE_DIR / sn / "program.json")

    if scope or oos:
        before = len(host_ports)
        host_ports = {h: ps for h, ps in host_ports.items() if is_in_scope(h, scope, oos)}
        dropped = before - len(host_ports)
        if dropped:
            print(f"     {colors.YELLOW}⏭  {dropped} host(s) filtered (out of scope){colors.RESET}")

    ps_file = ps_dir / "portscan.json"
    existing = {"scans": []}
    if ps_file.exists():
        try:
            existing = json.loads(ps_file.read_text())
        except Exception:
            pass

    scan_hosts = []
    for host in sorted(host_ports.keys()):
        port_service = host_ports[host]
        scan_hosts.append({
            "host": host,
            "ports": [
                {
                    "port": p,
                    "service": port_service[p].get("name", ""),
                    "product": port_service[p].get("product", ""),
                    "tls": port_service[p].get("tls", False),
                }
                for p in sorted(port_service.keys(), key=lambda x: int(x))
            ],
        })

    total_ports = sum(len(v) for v in host_ports.values())

    existing["scans"].append({
        "timestamp": ts,
        "domain": domain,
        "program_name": prog_name,
        "source": "naabu",
        "hosts_scanned": len(host_ports),
        "total_ports": total_ports,
        "hosts": scan_hosts,
    })
    ps_file.write_text(json.dumps(existing, indent=4, ensure_ascii=False))

    lf = ps_dir / "lives-portscan.json"
    lives = json.loads(lf.read_text()) if lf.exists() else {}

    if scope or oos:
        before = len(lives)
        lives = {k: v for k, v in lives.items() if is_in_scope(k, scope, oos)}
        removed = before - len(lives)
        if removed:
            print(f"     {colors.YELLOW}⏭  {removed} stale host(s) removed (out of scope){colors.RESET}")

    new_hosts = 0
    new_ports = 0
    new_services = 0

    for host, port_service in host_ports.items():
        if host not in lives:
            lives[host] = {
                "domain": domain,
                "ports": [],
                "services": {},
                "products": {},
                "tls": {},
                "first_seen": ts,
                "last_seen": ts,
            }
            new_hosts += 1
        else:
            lives[host]["last_seen"] = ts
            lives[host].setdefault("services", {})
            lives[host].setdefault("products", {})
            lives[host].setdefault("tls", {})

        old_ports = set(lives[host].get("ports", []))
        old_services = lives[host].get("services", {})
        old_products = lives[host].get("products", {})
        old_tls = lives[host].get("tls", {})

        for p, info in port_service.items():
            if p not in old_ports:
                new_ports += 1
            name = info.get("name", "")
            product = info.get("product", "")
            tls = info.get("tls", False)

            if name and old_services.get(p) != name:
                new_services += 1
            old_services[p] = name or old_services.get(p, "")
            old_products[p] = product or old_products.get(p, "")
            old_tls[p] = tls

        lives[host]["ports"] = sorted(
            set(lives[host].get("ports", []) + list(port_service.keys())),
            key=lambda x: int(x),
        )
        lives[host]["services"] = old_services
        lives[host]["products"] = old_products
        lives[host]["tls"] = old_tls

    lf.write_text(json.dumps(lives, indent=4, ensure_ascii=False))

    print(f"     {colors.GREEN}💾 Saved → {ps_dir}{colors.RESET}")
    if new_hosts:
        print(f"     {colors.GREEN}🆕 {new_hosts} new hosts{colors.RESET}")
    if new_ports:
        print(f"     {colors.GREEN}🔌 {new_ports} new ports{colors.RESET}")
    if new_services:
        print(f"     {colors.GREEN}⚙️  {new_services} service(s) identified{colors.RESET}")
    total_ports_lives = sum(len(v["ports"]) for v in lives.values())
    print(f"     {colors.CYAN}📋 Total: {len(lives)} hosts, {total_ports_lives} ports{colors.RESET}")


def format_port_line(port_info: dict) -> str:
    name = port_info.get("name", "")
    product = port_info.get("product", "")
    if name and product:
        return f"{name}: {product}"
    if name:
        return name
    if product:
        return product
    return ""


def find_program(domain: str):
    for d in DATABASE_DIR.iterdir():
        if d.is_dir() and (d / "program.json").exists():
            try:
                data = json.loads((d / "program.json").read_text())
                if domain in data.get("scope", []):
                    return data.get("program_name", d.name)
            except Exception:
                pass
    return None


# =========================
# Main
# =========================

if __name__ == "__main__":
    fresh_only = "--fresh" in sys.argv
    all_mode = "--all" in sys.argv
    force = "--force" in sys.argv

    if all_mode:
        mode = f"{'(Fresh)' if fresh_only else '(All)'}{' [Force]' if force else ''}"
        print(f"{colors.CYAN}[{now()}] WatchTower — Port Scan {mode}{colors.RESET}\n")

        progs = get_all_programs()
        if not progs:
            print(f"{colors.RED}❌ No programs found.{colors.RESET}")
            sys.exit(1)

        total_hosts = 0
        for prog in progs:
            pn, pd = prog["name"], prog["path"]
            hosts, lives, skipped, cdn_info = get_hosts_to_scan(pd, fresh_only, force)

            if not hosts:
                msg = f"⚠️ No hosts to scan for {pn}"
                if fresh_only and skipped:
                    msg += f" ({skipped} already tested)"
                print(f"{colors.YELLOW}{msg}{colors.RESET}")
                continue

            print(f"{colors.BLUE}{'─'*50}{colors.RESET}")
            print(f"{colors.BLUE}🔌 {pn} — {len(hosts)} host(s){colors.RESET}")
            if skipped:
                print(f"     {colors.GRAY}({skipped} skipped - already tested){colors.RESET}")

            host_ports = run_portscan(hosts, cdn_info, pd)

            if fresh_only:
                mark_as_tested(pd, hosts, lives)

            if host_ports:
                domain = "unknown"
                for h in host_ports:
                    if h in lives:
                        domain = lives[h].get("domain", "unknown")
                        break
                save_results(pn, domain, host_ports)
                total_hosts += len(host_ports)
                for host in sorted(host_ports.keys()):
                    ps = host_ports[host]
                    parts = []
                    for p in sorted(ps.keys(), key=lambda x: int(x)):
                        label = format_port_line(ps[p])
                        parts.append(f"{p}({label})" if label else p)
                    print(f"     {colors.GREEN}{host}{colors.RESET}: "
                          f"{colors.GRAY}{', '.join(parts)}{colors.RESET}")
            else:
                print(f"     {colors.YELLOW}⚠️ No open ports found{colors.RESET}")
            print()

        print(f"{colors.GREEN}{'='*50}{colors.RESET}")
        print(f"{colors.GREEN}✅ Port scan complete | Hosts: {total_hosts}{colors.RESET}")

    elif len(sys.argv) > 1 and not sys.argv[1].startswith("--"):
        domain = sys.argv[1]
        prog_name = find_program(domain)
        if not prog_name:
            print(f"{colors.RED}Domain '{domain}' not found.{colors.RESET}")
            sys.exit(1)

        pd = DATABASE_DIR / sanitize(prog_name)
        hosts, lives, _, cdn_info = get_hosts_to_scan(pd, False)

        if not hosts:
            print(f"{colors.YELLOW}No HTTP hosts for {domain}{colors.RESET}")
            sys.exit(0)

        print(f"{colors.CYAN}[{now()}] Port scan for {domain}{colors.RESET}")
        host_ports = run_portscan(hosts, cdn_info, pd)

        if host_ports:
            save_results(prog_name, domain, host_ports)
            for host in sorted(host_ports.keys()):
                ps = host_ports[host]
                parts = []
                for p in sorted(ps.keys(), key=lambda x: int(x)):
                    label = format_port_line(ps[p])
                    parts.append(f"{p}({label})" if label else p)
                print(f"     {colors.GREEN}{host}{colors.RESET}: "
                      f"{colors.GRAY}{', '.join(parts)}{colors.RESET}")
        else:
            print(f"{colors.YELLOW}⚠️ No open ports found{colors.RESET}")

    else:
        print("Usage:")
        print("  python3 watch_portscan.py <domain>")
        print("  python3 watch_portscan.py --all")
        print("  python3 watch_portscan.py --all --fresh")
        print("  python3 watch_portscan.py --all --fresh --force")