#!/bin/bash
# ======================================================
# WatchTower - Automated Pipeline Runner
# Runs all modules sequentially, logs output, and notifies.
# ======================================================

# Ensure Python flushes output line-by-line even when piped through `tee`.
# Without this, `print()` inside the modules is block-buffered (~8KB) and
# the terminal shows nothing until a module finishes.
export PYTHONUNBUFFERED=1

# =========================
# Colors
# =========================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
RESET='\033[0m'

# =========================
# Paths
# =========================
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DATABASE_DIR="$SCRIPT_DIR/database"
PROGRAMS_DIR="$SCRIPT_DIR/programs"
LOCK_FILE="$SCRIPT_DIR/run.lock"

# =========================
# Pipeline switches
# =========================
RUN_SYNC=true

# ASN / CIDR / IP enrichment
RUN_ASNMAP=true
RUN_MAPCIDR=true
RUN_IPENRICH=true

RUN_ENUM=true
RUN_WILDCARD=true
RUN_WORDLIST=true
RUN_DNS=true
RUN_STATIC_BRUTE=true
RUN_DYNAMIC_BRUTE=true
RUN_PATTERN=true
RUN_FILTER_PRIVATE=true
RUN_HTTP=true
RUN_WHOIS=true
RUN_CDN=true
RUN_VHOST=true
RUN_PORTSCAN=true

# JS pipeline (consolidated js_enum.py)
RUN_JSENUM=true
JSENUM_FORCE=false

# JS Secrets (separate from js_enum — uses secret/watch_secret_all.py)
RUN_JS_SECRETS=true

RUN_SCREENSHOT=true
RUN_NUCLEI=true
RUN_NOTIFY=true
RUN_CLOUD_ENUM=true

NUCLEI_FRESH=true
PORTSCAN_FRESH=true
SCREENSHOT_FRESH=true

# Per-step flags for enrichment steps
MAPCIDR_FORCE=false
ASNMAP_FORCE=false
IPENRICH_FORCE=false
MAPCIDR_LIMIT=4096

NOTIFY_START=true
NOTIFY_COMPLETE=true
NOTIFY_ERRORS=true

CLEAN_PYCACHE=true
USE_LOCK=true

# =========================
# Lock Handling
# =========================

lock_is_stale() {
    [ -f "$LOCK_FILE" ] || return 1
    local pid
    pid=$(cat "$LOCK_FILE" 2>/dev/null | tr -d '[:space:]')
    [ -n "$pid" ] || return 0
    if kill -0 "$pid" 2>/dev/null; then
        return 1
    fi
    return 0
}

acquire_lock() {
    [ "$USE_LOCK" = true ] || return 0

    if [ -f "$LOCK_FILE" ]; then
        if lock_is_stale; then
            echo -e "${YELLOW}⚠️  Stale lock found (PID not running). Removing...${RESET}"
            rm -f "$LOCK_FILE"
        else
            local pid
            pid=$(cat "$LOCK_FILE" 2>/dev/null)
            echo -e "${YELLOW}⚠️  Another WatchTower instance is already running (PID $pid).${RESET}"
            echo -e "${YELLOW}   Lock file: $LOCK_FILE${RESET}"
            echo -e "${YELLOW}   Exiting without action.${RESET}"
            exit 0
        fi
    fi

    echo $$ > "$LOCK_FILE"
    echo -e "${GRAY}🔒 Lock acquired (PID $$)${RESET}"
}

release_lock() {
    [ "$USE_LOCK" = true ] || return 0
    if [ -f "$LOCK_FILE" ]; then
        local pid
        pid=$(cat "$LOCK_FILE" 2>/dev/null | tr -d '[:space:]')
        if [ "$pid" = "$$" ]; then
            rm -f "$LOCK_FILE"
            echo -e "${GRAY}🔓 Lock released (PID $$)${RESET}"
        fi
    fi
}

trap release_lock EXIT INT TERM HUP

# =========================
# Log Setup
# =========================
get_next_log_number() {
    local program="$1"
    local log_dir="$DATABASE_DIR/$program/log"
    local num=1
    mkdir -p "$log_dir"
    while [ -f "$log_dir/log${num}.txt" ]; do
        num=$((num + 1))
    done
    echo "$num"
}

setup_log() {
    local program="$1"
    local log_num
    log_num=$(get_next_log_number "$program")
    echo "$DATABASE_DIR/$program/log/log${log_num}.txt"
}

# =========================
# Housekeeping
# =========================
clean_pycache() {
    if [ "$CLEAN_PYCACHE" = true ]; then
        find "$SCRIPT_DIR" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
        echo -e "${GRAY}🧹 Cleaned __pycache__ dirs${RESET}"
    fi
}

# =========================
# Banner
# =========================
banner() {
    echo -e "${MAGENTA}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║                🏰 WATCHTOWER RUNNER                  ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${RESET}"
}

# =========================
# Run Module
# =========================
run_module() {
    local step="$1"
    local name="$2"
    local log_file="$3"
    shift 3

    echo -e "${BLUE}┌──────────────────────────────────────────────────────┐${RESET}"
    echo -e "${BLUE}│${RESET} ${WHITE}Step ${step}: ${name}${RESET}"
    echo -e "${BLUE}│${RESET} ${GRAY}Command: $*${RESET}"
    echo -e "${BLUE}└──────────────────────────────────────────────────────┘${RESET}"
    echo ""

    {
        echo "======================================================"
        echo "Step ${step}: ${name}"
        echo "Command: $*"
        echo "Started: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "======================================================"
        echo ""
    } >> "$log_file"

    "$@" 2>&1 | tee -a "$log_file"
    local exit_code=${PIPESTATUS[0]}

    echo ""

    if [ $exit_code -eq 0 ]; then
        echo -e "${GREEN}✅ Step ${step} completed successfully${RESET}"
        {
            echo ""
            echo "Step ${step} completed: $(date '+%Y-%m-%d %H:%M:%S')"
            echo "Status: SUCCESS"
            echo ""
        } >> "$log_file"
    else
        echo -e "${YELLOW}⚠️  Step ${step} finished with exit code ${exit_code}${RESET}"
        {
            echo ""
            echo "Step ${step} completed: $(date '+%Y-%m-%d %H:%M:%S')"
            echo "Status: exit code ${exit_code}"
            echo ""
        } >> "$log_file"
    fi

    echo ""
    return $exit_code
}

# =========================
# Program Helper
# =========================
get_program_name() {
    if [ -d "$DATABASE_DIR" ]; then
        for dir in "$DATABASE_DIR"/*/; do
            [ -d "$dir" ] || continue
            local name
            name=$(basename "$dir")
            if [ "$name" != "log" ] && [ "$name" != "_adhoc" ] && [ -f "$dir/program.json" ]; then
                echo "$name"
                return
            fi
        done
    fi
    echo "default"
}

# =========================
# Notifications
# =========================
notify() {
    local message="$1"
    local encoded
    encoded=$(printf '%s' "$message" | base64 -w 0 2>/dev/null || printf '%s' "$message" | base64)
    TG_MSG_B64="$encoded" python3 -c "
import os, base64, sys, importlib.util
sys.path.insert(0, '$SCRIPT_DIR')
spec = importlib.util.spec_from_file_location('tg', '$SCRIPT_DIR/notifications/telegram.py')
tg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tg)
msg = base64.b64decode(os.environ['TG_MSG_B64']).decode('utf-8')
tg.send(msg)
" 2>/dev/null || true
}

notify_pipeline_start() {
    [ "$NOTIFY_START" = true ] || return 0
    notify "🚀 <b>WatchTower Pipeline Started</b>
📦 Program: <code>$1</code>
🕐 $(date '+%Y-%m-%d %H:%M:%S')"
}

notify_pipeline_complete() {
    [ "$NOTIFY_COMPLETE" = true ] || return 0
    notify "✅ <b>WatchTower Pipeline Complete</b>
📦 Program: <code>$1</code>
🕐 $(date '+%Y-%m-%d %H:%M:%S')"
}

notify_error() {
    [ "$NOTIFY_ERRORS" = true ] || return 0
    notify "❌ <b>WatchTower Step Failed</b>
📦 Program: <code>$1</code>
⚠️ Step: <code>$2</code>
🕐 $(date '+%Y-%m-%d %H:%M:%S')"
}

# =========================
# Main
# =========================
main() {
    acquire_lock
    banner
    clean_pycache

    START_TIME=$(date '+%Y-%m-%d %H:%M:%S')
    echo -e "${CYAN}Started: ${START_TIME}${RESET}"
    echo ""

    # =============================================
    # Step 1: Sync Programs
    # =============================================
    if [ "$RUN_SYNC" = true ]; then
        TEMP_LOG="/tmp/watchtower_sync_$$.log"
        run_module 1 "Sync Programs" "$TEMP_LOG" \
            python3 "$SCRIPT_DIR/programs/watch_sync_programs.py" "$PROGRAMS_DIR"

        PROGRAM_NAME=$(get_program_name)
        LOG_FILE=$(setup_log "$PROGRAM_NAME")

        if [ -f "$TEMP_LOG" ]; then
            cat "$TEMP_LOG" >> "$LOG_FILE"
            rm -f "$TEMP_LOG"
        fi

        echo -e "${CYAN}Program: ${PROGRAM_NAME}${RESET}"
        echo -e "${GRAY}📝 Log:     ${LOG_FILE}${RESET}"
        echo ""

        notify_pipeline_start "$PROGRAM_NAME"
    else
        PROGRAM_NAME=$(get_program_name)
        LOG_FILE=$(setup_log "$PROGRAM_NAME")
        echo -e "${CYAN}Program: ${PROGRAM_NAME}${RESET}"
        echo -e "${GRAY}📝 Log:     ${LOG_FILE}${RESET}"
        echo ""
    fi

    # =============================================
    # Step 1.5: ASN Map (asnmap)
    # =============================================
    if [ "$RUN_ASNMAP" = true ]; then
        ASNMAP_ARGS=""
        [ "$ASNMAP_FORCE" = true ] && ASNMAP_ARGS="$ASNMAP_ARGS --force"
        run_module "1.5" "ASN Map" "$LOG_FILE" \
            python3 "$SCRIPT_DIR/utils/watch_asnmap_all.py" $ASNMAP_ARGS \
            || notify_error "$PROGRAM_NAME" "ASN Map"
    fi

    # =============================================
    # Step 1.6: CIDR Map (mapcidr)
    # =============================================
    if [ "$RUN_MAPCIDR" = true ]; then
        MAPCIDR_ARGS="--limit $MAPCIDR_LIMIT"
        [ "$MAPCIDR_FORCE" = true ] && MAPCIDR_ARGS="$MAPCIDR_ARGS --force"
        run_module "1.6" "CIDR Map" "$LOG_FILE" \
            python3 "$SCRIPT_DIR/utils/watch_mapcidr_all.py" $MAPCIDR_ARGS \
            || notify_error "$PROGRAM_NAME" "CIDR Map"
    fi

    # =============================================
    # Step 1.7: IP Enrichment
    # =============================================
    if [ "$RUN_IPENRICH" = true ]; then
        IPENRICH_ARGS=""
        [ "$IPENRICH_FORCE" = true ] && IPENRICH_ARGS="$IPENRICH_ARGS --force"
        run_module "1.7" "IP Enrichment" "$LOG_FILE" \
            python3 "$SCRIPT_DIR/utils/watch_ip_all.py" $IPENRICH_ARGS \
            || notify_error "$PROGRAM_NAME" "IP Enrichment"
    fi

    # =============================================
    # Step 2: Enum All
    # =============================================
    if [ "$RUN_ENUM" = true ]; then
        run_module 2 "Enum Subdomains" "$LOG_FILE" \
            python3 "$SCRIPT_DIR/enumeration/watch_enum_all.py" \
            || notify_error "$PROGRAM_NAME" "Enum Subdomains"
    fi

    # =============================================
    # Step 3: Wildcard DNS Test
    # =============================================
    if [ "$RUN_WILDCARD" = true ]; then
        run_module 3 "Wildcard DNS Test" "$LOG_FILE" \
            python3 "$SCRIPT_DIR/dns/wildcard/watch_wildcard_dns_test_all.py" \
            || notify_error "$PROGRAM_NAME" "Wildcard DNS Test"
    fi

    # =============================================
    # Step 4: Wordlist Enhancer
    # =============================================
    if [ "$RUN_WORDLIST" = true ]; then
        run_module "4.1" "Subdomain Wordlist" "$LOG_FILE" \
            python3 "$SCRIPT_DIR/wordlist/subdomain/watch_subdomain_wordlist_all.py" \
            || notify_error "$PROGRAM_NAME" "Subdomain Wordlist"

        run_module "4.2" "VHost Wordlist" "$LOG_FILE" \
            python3 "$SCRIPT_DIR/wordlist/vhost/watch_vhost_wordlist_all.py" \
            || notify_error "$PROGRAM_NAME" "VHost Wordlist"
    fi

    # =============================================
    # Step 5: DNS Resolution
    # =============================================
    if [ "$RUN_DNS" = true ]; then
        run_module 5 "DNS Resolution" "$LOG_FILE" \
            python3 "$SCRIPT_DIR/dns/watch_dns_all.py" \
            || notify_error "$PROGRAM_NAME" "DNS Resolution"
    fi

    # =============================================
    # Step 6: Static DNS Brute Force
    # =============================================
    # if [ "$RUN_STATIC_BRUTE" = true ]; then
    #     run_module 6 "Static DNS Brute Force" "$LOG_FILE" \
    #         python3 "$SCRIPT_DIR/dns/static-brute/watch_static_dns_brute_all.py" \
    #         || notify_error "$PROGRAM_NAME" "Static DNS Brute Force"
    # fi

    # =============================================
    # Step 7: Dynamic DNS Brute Force
    # =============================================
    # if [ "$RUN_DYNAMIC_BRUTE" = true ]; then
    #     run_module 7 "Dynamic DNS Brute Force" "$LOG_FILE" \
    #         python3 "$SCRIPT_DIR/dns/dynamic-brute/watch_dynamic_dns_brute_all.py" \
    #         || notify_error "$PROGRAM_NAME" "Dynamic DNS Brute Force"
    # fi

    # =============================================
    # Step 8: Pattern Recognition
    # =============================================
    # if [ "$RUN_PATTERN" = true ]; then
    #     run_module 8 "Pattern Recognition" "$LOG_FILE" \
    #         python3 "$SCRIPT_DIR/dns/pattern-recognition/watch_pattern_recognition_all.py" \
    #         || notify_error "$PROGRAM_NAME" "Pattern Recognition"
    # fi

    # =============================================
    # Step 9: Filter Private IPs
    # =============================================
    if [ "$RUN_FILTER_PRIVATE" = true ]; then
        run_module 9 "Filter Private IPs" "$LOG_FILE" \
            python3 "$SCRIPT_DIR/dns/watch_privates_ip_filter_all.py" \
            || notify_error "$PROGRAM_NAME" "Filter Private IPs"
    fi

    # =============================================
    # Step 10: HTTP Probing
    # =============================================
    if [ "$RUN_HTTP" = true ]; then
        run_module 10 "HTTP Probing" "$LOG_FILE" \
            python3 "$SCRIPT_DIR/http/watch_httpx_all.py" \
            || notify_error "$PROGRAM_NAME" "HTTP Probing"
    fi

    # =============================================
    # Step 11: CDN / Cloud / WAF Detection
    # =============================================
    if [ "$RUN_CDN" = true ]; then
        run_module 11 "CDN/Cloud/WAF Detection" "$LOG_FILE" \
            python3 "$SCRIPT_DIR/cdn/watch_cdn_all.py" \
            || notify_error "$PROGRAM_NAME" "CDN Detection"
    fi

    # =============================================
    # Step 12: WHOIS / RDAP
    # =============================================
    if [ "$RUN_WHOIS" = true ]; then
        run_module 12 "WHOIS / RDAP" "$LOG_FILE" \
            python3 "$SCRIPT_DIR/whois/watch_whois_all.py" \
            || notify_error "$PROGRAM_NAME" "WHOIS / RDAP"
    fi

    # =============================================
    # Step 13: Port Scan
    # =============================================
    if [ "$RUN_PORTSCAN" = true ]; then
        if [ "$PORTSCAN_FRESH" = true ]; then
            run_module 13 "Port Scan (Fresh)" "$LOG_FILE" \
                python3 "$SCRIPT_DIR/portscan/watch_portscan_all.py" --fresh \
                || notify_error "$PROGRAM_NAME" "Port Scan"
        else
            run_module 13 "Port Scan" "$LOG_FILE" \
                python3 "$SCRIPT_DIR/portscan/watch_portscan_all.py" \
                || notify_error "$PROGRAM_NAME" "Port Scan"
        fi
    fi

    # =============================================
    # Step 14: Virtual Host Discovery
    # =============================================
    if [ "$RUN_VHOST" = true ]; then
        run_module 14 "Virtual Host Discovery" "$LOG_FILE" \
            python3 "$SCRIPT_DIR/vhost/watch_vhost_all.py" \
            || notify_error "$PROGRAM_NAME" "Virtual Host Discovery"
    fi

    # =============================================
    # Step 15: JS Enumeration Pipeline
    # =============================================
    if [ "$RUN_JSENUM" = true ]; then
        JS_ARGS=""
        [ "$JSENUM_FORCE" = true ] && JS_ARGS="--force"
        run_module "15" "JS Enumeration" "$LOG_FILE" \
            python3 "$SCRIPT_DIR/js/watch_js_enum_all.py" $JS_ARGS \
            || notify_error "$PROGRAM_NAME" "JS Enumeration"
    fi

    # =============================================
    # Step 15.5: JS Secrets (separate from js_enum)
    # =============================================
    if [ "$RUN_JS_SECRETS" = true ]; then
        run_module "15.5" "JS Secrets" "$LOG_FILE" \
            python3 "$SCRIPT_DIR/secret/watch_secret_all.py" \
            || notify_error "$PROGRAM_NAME" "JS Secrets"
    fi

    # =============================================
    # Step 16: Screenshots
    # =============================================
    if [ "$RUN_SCREENSHOT" = true ]; then
        if [ "$SCREENSHOT_FRESH" = true ]; then
            run_module 16 "Screenshots (Fresh)" "$LOG_FILE" \
                python3 "$SCRIPT_DIR/screenshot/watch_screenshot_all.py" --fresh \
                || notify_error "$PROGRAM_NAME" "Screenshots"
        else
            run_module 16 "Screenshots" "$LOG_FILE" \
                python3 "$SCRIPT_DIR/screenshot/watch_screenshot_all.py" \
                || notify_error "$PROGRAM_NAME" "Screenshots"
        fi
    fi

    # =============================================
    # Step 17: Nuclei
    # =============================================
    if [ "$RUN_NUCLEI" = true ]; then
        run_module 17 "Nuclei URL Maker" "$LOG_FILE" \
            python3 "$SCRIPT_DIR/attack/nuclei/nuclei_url_maker.py" --all \
            || notify_error "$PROGRAM_NAME" "Nuclei URL Maker"

        if [ "$NUCLEI_FRESH" = true ]; then
            run_module "17.5" "Nuclei (Fresh)" "$LOG_FILE" \
                python3 "$SCRIPT_DIR/attack/nuclei/watch_nuclei_fresh.py" \
                || notify_error "$PROGRAM_NAME" "Nuclei"
        else
            run_module "17.5" "Nuclei (All)" "$LOG_FILE" \
                python3 "$SCRIPT_DIR/attack/nuclei/watch_nuclei_all.py" \
                || notify_error "$PROGRAM_NAME" "Nuclei"
        fi
    fi

    # =============================================
    # Step 18/19: Notifications (handled inline by notify_* helpers)
    # =============================================
    # if [ "$RUN_NOTIFY" = true ]; then
    #     run_module 18 "Telegram Notification" "$LOG_FILE" \
    #         python3 "$SCRIPT_DIR/notifications/telegram.py" \
    #         || true
    #     run_module 19 "Discord Notification" "$LOG_FILE" \
    #         python3 "$SCRIPT_DIR/notifications/discord.py" \
    #         || true
    # fi

    END_TIME=$(date '+%Y-%m-%d %H:%M:%S')

    echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${RESET}"
    echo -e "${GREEN}║              ✅ PIPELINE COMPLETED!                  ║${RESET}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${RESET}"
    echo ""
    echo -e "${CYAN}Started: ${START_TIME}${RESET}"
    echo -e "${CYAN}Ended:   ${END_TIME}${RESET}"
    echo -e "${GRAY}Log:     ${LOG_FILE}${RESET}"
    echo ""

    {
        echo ""
        echo "╔══════════════════════════════════════════════════════╗"
        echo "║              ✅ PIPELINE COMPLETED!                  ║"
        echo "╚══════════════════════════════════════════════════════╝"
        echo ""
        echo "Started: $START_TIME"
        echo "Ended:   $END_TIME"
        echo ""
    } >> "$LOG_FILE"

    clean_pycache
    notify_pipeline_complete "$PROGRAM_NAME"
}

main