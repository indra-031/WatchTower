<p align="center">
  <img src="ui/static/images/logo.svg" width="120" alt="WatchTower">
</p>

<h1 align="center">🏰 WATCHTOWER</h1>

<p align="center">
  <b>Automated Recon & Vulnerability Scanning Pipeline</b><br>
  <i>Enumerate. Resolve. Probe. Analyze. Attack. Report.</i>
</p>

<p align="center">
  <a href="https://github.com/indra-031/WatchTower"><img alt="Repo" src="https://img.shields.io/badge/github-indra--031%2FWatchTower-181717?style=flat-square&logo=github"></a>
  <img alt="Python" src="https://img.shields.io/badge/python-3.10+-3776AB?style=flat-square&logo=python&logoColor=white">
  <img alt="License" src="https://img.shields.io/badge/license-MIT-green?style=flat-square">
  <img alt="Platform" src="https://img.shields.io/badge/platform-linux-lightgrey?style=flat-square&logo=linux&logoColor=black">
</p>

---

## 🎯 What is WatchTower?

WatchTower is a modular, file-based recon pipeline for bug bounty hunters
and pentesters. It chains together best-in-class tools — subfinder, httpx,
nuclei, katana, dnsx, and friends — into a single automated flow with:

- **Per-program isolation** — every target keeps its own database
- **Incremental scanning** — skip what's already been tested
- **Change detection** — diff HTTP / DNS / JS state between runs
- **Scope enforcement** — `out_of_scope` always wins over `scope`
- **Web dashboard** — browse everything from a Flask UI
- **Notifications** — Telegram & Discord alerts for new findings

No database server. No cloud. Just files on disk.

---

## 🚀 Quick Start

### 1. Clone & install

    git clone https://github.com/indra-031/WatchTower.git
    cd WatchTower
    python3 install/setup.py

The installer handles Python packages, Go tools, Rust tools, and
Playwright's Chromium browser. Run the status check any time:

    python3 install/setup.py --check

### 2. Configure

Edit `configs/api-keys.json`:

    {
        "chaos_api_key": "YOUR_CHAOS_API_KEY",
        "abuseipdb_api_key": "YOUR_ABUSEIPDB_API_KEY",
        "github_token": "YOUR_GITHUB_TOKEN"
    }

Edit `configs/notifications.json` to enable Telegram or Discord
alerts. Both are optional — leave `"enabled": false` to disable.

**Never commit these files.** They are already in `.gitignore`.

### 3. Add a program

Drop a JSON file into `programs/` — the filename becomes the program
name (e.g. `programs/walmart.json`):

    {
        "program_name": "walmart",
        "scope": [
            "walmart.com",
            "wal-mart.com"
        ],
        "out_of_scope": [
            "careers.walmart.com"
        ],
        "cidr": [
            "192.0.2.0/24"
        ],
        "asn": [
            "AS15169"
        ],
        "ip": [
            "198.51.100.120"
        ]
    }

All fields except `program_name` and `scope` are optional.
A ready-to-edit example lives in `programs/example._json`.

### 4. Run

    bash watch.sh

Sit back. Logs stream to the terminal and to
`database/<program>/log/logN.txt`. When it finishes, every phase's
output is ready in `database/<program>/`.

---

## 🧩 Features

| Phase | Tools | Output |
|---|---|---|
| **Enrichment** | asnmap, mapcidr, ip | ASN → CIDR → IP expansion |
| **Enumeration** | subfinder, crt.sh, chaos, wayback, gau, crtmon, crt.name, agniops, assetfinder, waymore, findomain, github-subdomains | Subdomain discovery |
| **DNS** | shuffledns, dnsx, dnsgen | Resolution + brute-force + wildcard |
| **HTTP** | httpx | Status, title, tech, favicon, content hash |
| **CDN / WAF** | cdncheck | CDN / cloud / WAF detection |
| **Port Scan** | naabu | Open ports + service fingerprint |
| **VHost** | custom | Host-header fuzzing |
| **WHOIS** | RDAP | Registration data |
| **JS Analysis** | katana, subjs, getJS, gau, sitemap, waybackurls, xnLinkFinder | Download, extract, merge |
| **Secret Scan** | trufflehog, gitleaks, semgrep, shhgit, jsluice, secretfinder, detect-secrets, dumpsterdiver, vscan | 9 scanners in one run |
| **Attack** | nuclei | Template-based vulnerability scan |
| **Reporting** | custom | Screenshots, notifications, HTML dashboard |

---

## 📂 Directory Structure

    WatchTower/
    ├── attack/          # Nuclei orchestration
    ├── cdn/             # CDN detection
    ├── configs/         # API keys, scope, colors, changes
    ├── database/        # Per-program output (gitignored)
    ├── dns/             # Resolution & brute-force
    ├── enumeration/     # Passive subdomain sources
    ├── http/            # HTTP probing
    ├── install/         # setup.py + requirements.txt
    ├── js/              # JS enumeration pipeline
    ├── notifications/   # Telegram / Discord
    ├── portscan/        # Port scanning
    ├── programs/        # ← your targets live here
    ├── screenshot/      # Playwright screenshots
    ├── secret/          # Secret scanners
    ├── ui/              # Flask dashboard (HTML/CSS/JS)
    ├── utils/           # ASN / CIDR / IP helpers
    ├── vhost/           # Virtual host discovery
    ├── whois/           # RDAP lookups
    ├── wordlist/        # Auto-growing wordlists
    ├── app.py           # Flask server
    └── watch.sh         # Main pipeline

---

## 🖥️ Web Dashboard

Start the dashboard:

    python3 app.py

Open `http://localhost:5000`. The UI reads everything from
`database/<program>/` — no database server required.

Pages include:

- **Dashboard** — global stats and per-program counts
- **Subdomains** — all, fresh (24h), live
- **HTTP Assets** — full and fresh
- **Port Scan** — open ports per host
- **Screenshots** — visual gallery
- **Attack / Nuclei** — findings sorted by severity
- **Changes** — diff log across runs
- **Advanced Search** — multi-filter across every module
- **Bookmark / Works** — your own journal (localStorage)

---

## 🔔 Notifications

### Telegram

1. Message `@BotFather` → `/newbot` → copy the token
2. Add the bot to your group and send `/start`
3. Get `chat_id` (e.g. via `@userinfobot`)
4. Set `enabled: true` in `configs/notifications.json`
   (and `topic_id` if using a supergroup topic)

### Discord

1. Server Settings → Integrations → Webhooks → New
2. Copy the URL into `webhook_url`
3. Set `enabled: true`

---

## 🔐 Security Notes

- `configs/api-keys.json` and `configs/notifications.json` are in
  `.gitignore` — **never commit them**
- Use `configs/*.example.json` templates as starting points
- Rotate keys immediately if accidentally exposed
- Scope enforcement is applied at write-time on every module
- `out_of_scope` always wins over `scope`

---

## ⚙️ Advanced Options

    # Full pipeline on all programs
    bash watch.sh

    # Individual modules
    python3 enumeration/watch_enum_all.py
    python3 dns/watch_dns_all.py
    python3 http/watch_httpx_all.py
    python3 attack/nuclei/watch_nuclei_all.py --fresh

    # Installer: partial installs
    python3 install/setup.py --python
    python3 install/setup.py --go-tools
    python3 install/setup.py --cargo-tools
    python3 install/setup.py --playwright
    python3 install/setup.py --git-tools
    python3 install/setup.py --check

---

## ⚠️ Disclaimer

WatchTower is intended for **authorized security testing only**.
Do not use it against targets you don't have explicit permission to
test. The authors are not responsible for any misuse.

**Hunt responsibly.**