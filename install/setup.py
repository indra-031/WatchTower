#!/usr/bin/env python3
"""
WatchTower - Installer (BETA)

This file lives in install/, so it resolves the project root as its
parent directory. Run it from anywhere:

    python3 install/setup.py
    python3 install/setup.py --check

Covered:
  Python  : flask, requests, waymore, dnsgen, playwright,
            beautifulsoup4, xnLinkFinder, detect-secrets, semgrep
  Browsers: playwright Chromium (auto-installed after playwright)
  Go      : asnmap, mapcidr, subfinder, assetfinder, chaos, gau,
            github-subdomains, shuffledns, dnsx, massdns,
            httpx, naabu, cdncheck, nuclei,
            katana, waybackurls, subjs, getJS,
            trufflehog, shhgit, jsluice, gitleaks
  Git     : SecretFinder, DumpsterDiver  (cloned to .tools/)
  Rust    : findomain
  Zips    : dns/brute-files/*.zip → extracted wordlists

Manual (unverified repo):
  crtmon

Data dependencies (not installed here):
  dns/brute-files/*.txt
  wordlist/{vhost,subdomain,parameter}/*.txt
  attack/nuclei/nuclei-public.yaml
  configs/semgrep/{js-secrets.yml,html-secrets.yml}
  configs/shhgit/                    (config + signatures)

Usage:
  python3 install/setup.py                    # install everything
  python3 install/setup.py --check            # status only
  python3 install/setup.py --python           # python packages only
  python3 install/setup.py --go-tools         # go tools only
  python3 install/setup.py --cargo-tools      # rust tools only
  python3 install/setup.py --git-tools        # git clones only
  python3 install/setup.py --playwright       # playwright browsers only
  python3 install/setup.py --unzip            # extract brute-files zips only
  python3 install/setup.py --update           # force upgrade / reinstall
"""

import argparse
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


# =========================
# Paths
# =========================
# This file is <repo>/install/setup.py
#   INSTALL_DIR = <repo>/install
#   BASE_DIR    = <repo>

INSTALL_DIR = Path(__file__).resolve().parent
BASE_DIR = INSTALL_DIR.parent

REQUIREMENTS_FILE = INSTALL_DIR / "requirements.txt"
API_KEYS_FILE = BASE_DIR / "configs" / "api-keys.json"
NOTIFICATIONS_FILE = BASE_DIR / "configs" / "notifications.json"
RESOLVERS_FILE = BASE_DIR / "dns" / "brute-files" / "resolvers.txt"
NUCLEI_CONFIG = BASE_DIR / "attack" / "nuclei" / "nuclei-public.yaml"
TOOLS_DIR = BASE_DIR / ".tools"
ZIP_DIR = BASE_DIR / "dns" / "brute-files"


# =========================
# Configuration
# =========================

MIN_PYTHON = (3, 10)

PYTHON_PACKAGES = [
    "flask",
    "requests",
    "waymore",
    "dnsgen",
    "playwright",
    "beautifulsoup4",
    "xnLinkFinder",
    "detect-secrets",
    "semgrep",
]

GO_TOOLS = [
    ("asnmap",             "github.com/projectdiscovery/asnmap/cmd/asnmap@latest"),
    ("mapcidr",            "github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest"),
    ("subfinder",          "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
    ("assetfinder",        "github.com/tomnomnom/assetfinder@latest"),
    ("chaos",              "github.com/projectdiscovery/chaos-client/cmd/chaos@latest"),
    ("gau",                "github.com/lc/gau/v2/cmd/gau@latest"),
    ("github-subdomains",  "github.com/gwen001/github-subdomains@latest"),
    ("shuffledns",         "github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"),
    ("dnsx",               "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"),
    ("massdns",            "github.com/blechschmidt/massdns@latest"),
    ("httpx",              "github.com/projectdiscovery/httpx/cmd/httpx@latest"),
    ("naabu",              "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"),
    ("cdncheck",           "github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest"),
    ("nuclei",             "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"),
    ("katana",             "github.com/projectdiscovery/katana/cmd/katana@latest"),
    ("waybackurls",        "github.com/tomnomnom/waybackurls@latest"),
    ("subjs",              "github.com/lc/subjs@latest"),
    ("getJS",              "github.com/003random/getJS@latest"),
    ("trufflehog",         "github.com/trufflesecurity/trufflehog/v3@latest"),
    ("shhgit",             "github.com/eth0izzle/shhgit@latest"),
    ("jsluice",            "github.com/BishopFox/jsluice/cmd/jsluice@latest"),
    ("gitleaks",           "github.com/gitleaks/gitleaks/v8@latest"),
]

# (dir_name, git_url, expected_py_file)
GIT_TOOLS = [
    ("SecretFinder",
     "https://github.com/m4ll0k/SecretFinder.git",
     "SecretFinder.py"),
    ("DumpsterDiver",
     "https://github.com/securing/DumpsterDiver.git",
     "DumpsterDiver.py"),
]

CARGO_TOOLS = [
    ("findomain", "findomain"),
]

MANUAL_TOOLS = [
    ("crtmon", "real-time CRT monitor - verify repo and install manually"),
]

PLANNED_GO_TOOLS = []

REQUIRED_SYSTEM_BINS = ["bash", "curl", "git"]

INTERNAL_REQUIRED_FILES = [
    "configs/colors.py",
    "configs/scope.py",
    "configs/changes.py",
    "configs/hosts.py",
    "configs/api-keys.json",
    "configs/notifications.json",
    "secret/_shared.py",
]

REQUIRED_API_KEYS = {
    "chaos_api_key":     "chaos",
    "github_token":      "github-subdomains",
    "abuseipdb_api_key": "abuseipdb",
}

NOTIFICATION_KEYS = {
    "telegram": ["token", "chat_id"],
    "discord":  ["webhook_url"],
}

DATA_FILES = [
    ("dns/brute-files/resolvers.txt",             True),
    ("dns/brute-files/best-dns-wordlist.txt",     False),
    ("dns/brute-files/2m-subdomains.txt",         False),
    ("dns/brute-files/4_lower.txt",               False),
    ("dns/brute-files/altdns-words.txt",          False),
    ("dns/brute-files/dnsgen-words.txt",          False),
    ("wordlist/vhost/vhost.txt",                  False),
    ("wordlist/vhost/custom-vhost.txt",           False),
    ("wordlist/subdomain/custom-subdomain.txt",   False),
    ("wordlist/parameter/wordlist-parameter.txt", False),
    ("attack/nuclei/nuclei-public.yaml",          True),
    ("configs/semgrep/js-secrets.yml",            False),
    ("configs/semgrep/html-secrets.yml",          False),
    ("configs/shhgit/config.yaml",                False),
]


# =========================
# Colors
# =========================

class C:
    RED    = "\033[0;31m"
    GREEN  = "\033[0;32m"
    YELLOW = "\033[1;33m"
    CYAN   = "\033[0;36m"
    GRAY   = "\033[0;90m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"


def info(m): print(f"{C.CYAN}{m}{C.RESET}")
def ok(m):   print(f"{C.GREEN}{m}{C.RESET}")
def warn(m): print(f"{C.YELLOW}{m}{C.RESET}")
def err(m):  print(f"{C.RED}{m}{C.RESET}")
def dim(m):  print(f"{C.GRAY}{m}{C.RESET}")


# =========================
# Helpers
# =========================

def has_binary(name):
    return shutil.which(name) is not None


def run(cmd, cwd=None):
    dim("$ " + " ".join(cmd) + (f"  (cwd={cwd})" if cwd else ""))
    try:
        return subprocess.call(cmd, cwd=cwd)
    except FileNotFoundError:
        return 127


def check_python_version():
    return sys.version_info >= MIN_PYTHON


def pip_cmd():
    return [sys.executable, "-m", "pip"]


def gopath_bin():
    try:
        r = subprocess.run(["go", "env", "GOPATH"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            p = r.stdout.strip()
            if p:
                return str(Path(p) / "bin")
    except Exception:
        pass
    return None


def path_contains(p):
    return p in os.environ.get("PATH", "").split(os.pathsep)


def apt_install(package):
    if not has_binary("apt-get"):
        return False
    info(f"  attempting: apt-get install -y {package}")
    rc = run(["sudo", "-n", "apt-get", "install", "-y", package])
    return rc == 0


# =========================
# Playwright helpers
# =========================

def playwright_browsers_installed():
    cache = Path.home() / ".cache" / "ms-playwright"
    if not cache.exists():
        return False
    for d in cache.iterdir():
        if d.is_dir() and d.name.startswith("chromium-"):
            return True
    return False


def playwright_package_installed():
    try:
        import playwright  # noqa: F401
        return True
    except ImportError:
        return False


def install_playwright_browsers(force=False):
    info("\n[Installing Playwright Chromium]")
    if not playwright_package_installed():
        err("  playwright package not installed yet "
            "(install python packages first)")
        return False

    if playwright_browsers_installed() and not force:
        dim("  chromium: already installed, skipping")
        return True

    cmd = [sys.executable, "-m", "playwright", "install", "chromium"]
    if run(cmd) != 0:
        err("  playwright install chromium failed")
        dim("  On Debian/Ubuntu you may also need:")
        dim("    sudo apt install -y libnss3 libatk-bridge2.0-0 "
            "libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 "
            "libxrandr2 libgbm1 libpango-1.0-0 libcairo2 libasound2")
        return False
    ok("  chromium installed")
    return True


# =========================
# Git tool helpers
# =========================

def git_tool_installed(name, expected_file):
    return (TOOLS_DIR / name / expected_file).exists()


def install_git_tool(name, url, expected_file, force=False):
    target = TOOLS_DIR / name

    if git_tool_installed(name, expected_file) and not force:
        dim(f"  {name}: already installed, skipping")
        return True

    if target.exists() and force:
        try:
            shutil.rmtree(target)
        except Exception as e:
            warn(f"  {name}: could not remove existing dir: {e}")

    TOOLS_DIR.mkdir(parents=True, exist_ok=True)

    info(f"  cloning {name} → {target}")
    rc = run(["git", "clone", "--depth", "1", url, str(target)])
    if rc != 0:
        err(f"  failed to clone {name}")
        return False

    if not git_tool_installed(name, expected_file):
        err(f"  {name}: expected {expected_file} not found after clone")
        return False

    ok(f"  {name}: installed")
    return True


def install_git_tools(force=False):
    info("\n[Installing Git tools]")
    if not has_binary("git"):
        err("  git is not installed (apt install git)")
        return False

    all_ok = True
    for name, url, expected_file in GIT_TOOLS:
        if not install_git_tool(name, url, expected_file, force=force):
            all_ok = False

    for name, _, _ in GIT_TOOLS:
        req = TOOLS_DIR / name / "requirements.txt"
        if req.exists():
            info(f"  {name}: installing python deps from requirements.txt")
            if run(pip_cmd() + ["install", "-r", str(req)]) != 0:
                warn(f"  {name}: pip install requirements failed (non-fatal)")

    return all_ok


# =========================
# Brute-files unzip
# =========================

def unzip_brute_files(force=False):
    """Extract wordlists from dns/brute-files/*.zip.

    Skips members that already exist unless force=True. Rejects any
    member with absolute or parent-traversal paths (zip-slip defense).
    """
    if not ZIP_DIR.exists():
        dim(f"  {ZIP_DIR} does not exist, skipping")
        return True

    zips = sorted(ZIP_DIR.glob("*.zip"))
    if not zips:
        dim("  no zip files found in dns/brute-files/")
        return True

    all_ok = True
    for zf in zips:
        info(f"  extracting {zf.name} ({zf.stat().st_size // (1024 * 1024)} MB)")
        try:
            with zipfile.ZipFile(zf, "r") as z:
                for member in z.namelist():
                    if member.endswith("/"):
                        continue

                    # Zip-slip defense
                    mp = Path(member)
                    if mp.is_absolute() or ".." in mp.parts:
                        warn(f"    skip unsafe path: {member}")
                        continue

                    target = ZIP_DIR / member
                    if target.exists() and not force:
                        dim(f"    {member}: exists (use --update to overwrite)")
                        continue

                    z.extract(member, ZIP_DIR)
                    size_mb = target.stat().st_size / (1024 * 1024)
                    ok(f"    {member} ({size_mb:.1f} MB)")

        except zipfile.BadZipFile:
            err(f"  {zf.name}: corrupted zip")
            all_ok = False
        except Exception as e:
            err(f"  {zf.name}: {e}")
            all_ok = False

    return all_ok


# =========================
# Status reporting
# =========================

def show_python_status():
    info("\n[Python]")
    if not check_python_version():
        err(f"  python: {sys.version.split()[0]} "
            f"(need >= {MIN_PYTHON[0]}.{MIN_PYTHON[1]})")
        return
    ok(f"  python: {sys.version.split()[0]}")

    try:
        from importlib.metadata import version, PackageNotFoundError
        for pkg in PYTHON_PACKAGES:
            try:
                ok(f"  {pkg}: {version(pkg)}")
            except PackageNotFoundError:
                warn(f"  {pkg}: missing")
    except Exception:
        for pkg in PYTHON_PACKAGES:
            dim(f"  {pkg}: ?")

    info("\n[Playwright browsers]")
    if playwright_browsers_installed():
        ok("  chromium: installed")
    else:
        warn("  chromium: missing (run: playwright install chromium)")


def show_system_status():
    info("\n[System]")
    for b in REQUIRED_SYSTEM_BINS:
        if has_binary(b):
            ok(f"  {b}: ok")
        else:
            err(f"  {b}: missing")


def show_internal_status():
    info("\n[Internal files]")
    for rel in INTERNAL_REQUIRED_FILES:
        p = BASE_DIR / rel
        if p.exists():
            ok(f"  {rel}: ok")
        else:
            err(f"  {rel}: missing")

    if API_KEYS_FILE.exists():
        try:
            import json
            data = json.loads(API_KEYS_FILE.read_text(encoding="utf-8"))
            for key, label in REQUIRED_API_KEYS.items():
                val = data.get(key, "")
                if val:
                    ok(f"  {key}: set ({label})")
                else:
                    warn(f"  {key}: empty ({label} will be skipped)")
        except Exception as e:
            warn(f"  api-keys.json: parse error: {e}")

    if NOTIFICATIONS_FILE.exists():
        try:
            import json
            data = json.loads(NOTIFICATIONS_FILE.read_text(encoding="utf-8"))
            for channel, keys in NOTIFICATION_KEYS.items():
                cfg = data.get(channel, {}) or {}
                if not cfg.get("enabled", False):
                    dim(f"  {channel}: disabled")
                    continue
                missing = [k for k in keys if not cfg.get(k)]
                if missing:
                    warn(f"  {channel}: enabled but missing {', '.join(missing)}")
                else:
                    ok(f"  {channel}: enabled + configured")
        except Exception as e:
            warn(f"  notifications.json: parse error: {e}")


def show_data_status():
    info("\n[Data files]")
    for rel, required in DATA_FILES:
        p = BASE_DIR / rel
        if p.exists():
            try:
                if p.suffix == ".txt":
                    n = sum(1 for line in p.read_text(errors="ignore").splitlines()
                            if line.strip())
                    ok(f"  {rel}: {n} lines")
                else:
                    ok(f"  {rel}: ok")
            except Exception:
                warn(f"  {rel}: unreadable")
        else:
            if required:
                warn(f"  {rel}: missing (required)")
            else:
                dim(f"  {rel}: missing (optional)")


def show_go_status():
    info("\n[Go]")
    if not has_binary("go"):
        err("  go: not installed (https://go.dev/dl/)")
    else:
        try:
            r = subprocess.run(["go", "version"], capture_output=True, text=True)
            ok(f"  {r.stdout.strip() or 'go: installed'}")
        except Exception:
            ok("  go: installed")

    info("\n[Go tools]")
    for binary, _ in GO_TOOLS:
        if has_binary(binary):
            ok(f"  {binary}: installed")
        else:
            warn(f"  {binary}: missing")


def show_git_status():
    info("\n[Git tools]")
    if not TOOLS_DIR.exists():
        warn(f"  {TOOLS_DIR}: missing (run --git-tools)")
        return
    for name, _, expected in GIT_TOOLS:
        p = TOOLS_DIR / name / expected
        if p.exists():
            ok(f"  {name}: installed ({p})")
        else:
            warn(f"  {name}: missing")


def show_zip_status():
    info("\n[Brute-files zips]")
    if not ZIP_DIR.exists():
        warn(f"  {ZIP_DIR}: missing")
        return
    zips = sorted(ZIP_DIR.glob("*.zip"))
    if not zips:
        dim("  no zip files found")
        return
    for zf in zips:
        size_mb = zf.stat().st_size / (1024 * 1024)
        try:
            with zipfile.ZipFile(zf, "r") as z:
                members = [m for m in z.namelist() if not m.endswith("/")]
                ok(f"  {zf.name} ({size_mb:.1f} MB) — {len(members)} file(s)")
                for m in members:
                    extracted = (ZIP_DIR / m).exists()
                    mark = ok if extracted else dim
                    mark(f"    {m}: {'extracted' if extracted else 'not extracted'}")
        except zipfile.BadZipFile:
            err(f"  {zf.name}: corrupted")


def show_cargo_status():
    info("\n[Rust]")
    if not has_binary("cargo"):
        err("  cargo: not installed (https://rustup.rs/)")
        dim("  findomain can also be installed via: sudo apt install findomain")
    else:
        ok("  cargo: installed")

    info("\n[Rust tools]")
    for binary, _ in CARGO_TOOLS:
        if has_binary(binary):
            ok(f"  {binary}: installed")
        else:
            warn(f"  {binary}: missing")


def show_manual_status():
    info("\n[Manual tools]")
    for binary, hint in MANUAL_TOOLS:
        if has_binary(binary):
            ok(f"  {binary}: installed")
        else:
            warn(f"  {binary}: not installed — {hint}")


# =========================
# Installers
# =========================

def install_python_packages(upgrade=False):
    info("\n[Installing Python packages]")
    if not REQUIREMENTS_FILE.exists():
        err(f"  requirements.txt not found: {REQUIREMENTS_FILE}")
        return False
    cmd = pip_cmd() + ["install", "-r", str(REQUIREMENTS_FILE)]
    if upgrade:
        cmd.append("--upgrade")
    if run(cmd) != 0:
        err("  pip install failed")
        return False
    ok("  python packages installed")
    return True


def install_go_tools(force=False):
    info("\n[Installing Go tools]")
    if not has_binary("go"):
        err("  go is not installed. Install Go first: https://go.dev/dl/")
        return False

    all_ok = True
    for binary, path in GO_TOOLS:
        if has_binary(binary) and not force:
            dim(f"  {binary}: already installed, skipping")
            continue
        info(f"  installing {binary} ...")
        rc = run(["go", "install", path])
        if rc == 0 and has_binary(binary):
            ok(f"  {binary}: installed")
            continue

        if binary == "massdns":
            warn(f"  go install failed for {binary}, trying apt ...")
            if apt_install("massdns"):
                ok(f"  {binary}: installed via apt")
                continue

        err(f"  failed: {binary}")
        all_ok = False

    gp = gopath_bin()
    if gp and not path_contains(gp):
        warn(f'  add to PATH: export PATH="$PATH:{gp}"')

    return all_ok


def install_cargo_tools(force=False):
    info("\n[Installing Rust tools]")
    if not has_binary("cargo"):
        err("  cargo is not installed. Install Rust first: https://rustup.rs/")
        dim("  Or: sudo apt install findomain")
        return False

    all_ok = True
    for binary, crate in CARGO_TOOLS:
        if has_binary(binary) and not force:
            dim(f"  {binary}: already installed, skipping")
            continue
        info(f"  installing {binary} via cargo ...")
        if run(["cargo", "install", crate]) != 0:
            err(f"  failed: {binary}")
            all_ok = False
        else:
            ok(f"  {binary}: installed")

    return all_ok


# =========================
# Main
# =========================

def main():
    p = argparse.ArgumentParser(description="WatchTower installer (beta)")
    p.add_argument("--check", action="store_true",
                   help="status only, no installs")
    p.add_argument("--python", action="store_true",
                   help="install python packages only")
    p.add_argument("--go-tools", action="store_true",
                   help="install go tools only")
    p.add_argument("--cargo-tools", action="store_true",
                   help="install rust tools only")
    p.add_argument("--git-tools", action="store_true",
                   help="clone git-based tools into .tools/")
    p.add_argument("--playwright", action="store_true",
                   help="install playwright browsers only")
    p.add_argument("--unzip", action="store_true",
                   help="extract dns/brute-files/*.zip only")
    p.add_argument("--update", action="store_true",
                   help="force upgrade / reinstall")
    a = p.parse_args()

    print(f"{C.BOLD}{C.CYAN}")
    print("=" * 56)
    print("             WatchTower Installer (BETA)")
    print("=" * 56)
    print(f"{C.RESET}")

    if a.check:
        show_python_status()
        show_system_status()
        show_internal_status()
        show_data_status()
        show_go_status()
        show_git_status()
        show_zip_status()
        show_cargo_status()
        show_manual_status()
        return 0

    only = (a.python or a.go_tools or a.cargo_tools
            or a.playwright or a.git_tools or a.unzip)
    do_python = a.python or not only
    do_go = a.go_tools or not only
    do_cargo = a.cargo_tools or not only
    do_git = a.git_tools or not only
    do_pw = a.playwright or not only
    do_unzip = a.unzip or not only

    if do_python:
        show_python_status()
        show_system_status()
        show_internal_status()
        if not install_python_packages(upgrade=a.update):
            return 1

    if do_pw:
        if not install_playwright_browsers(force=a.update):
            warn("  Playwright browser install failed — screenshots will not work")

    if do_go:
        show_go_status()
        if not install_go_tools(force=a.update):
            return 1

    if do_git:
        if not install_git_tools(force=a.update):
            warn("  some git tools failed — secret scanners may not work")

    if do_unzip:
        info("\n[Extracting brute-force wordlists]")
        if not unzip_brute_files(force=a.update):
            warn("  some zips failed to extract — check them manually")

    if do_cargo:
        show_cargo_status()
        if not install_cargo_tools(force=a.update):
            return 1

    show_manual_status()
    show_data_status()
    ok("\nDone.")
    return 0


if __name__ == "__main__":
    sys.exit(main())