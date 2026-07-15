#!/bin/sh
# uninstall.sh — remove the custom-whisper integration from a Wazuh manager.
#
# Mirrors install.sh: deletes the marker-delimited ossec.conf block, removes the
# installed files, restarts the manager and verifies the integration is gone.
# Run AS ROOT on the manager.
#
# Usage:
#   uninstall.sh [--purge] [--skip-template]
#                [--indexer-url URL] [--indexer-user USER] [--indexer-pass PASS]
#
#   --purge          Also remove the API key file and the dedup cache
#                    (default keeps both so a reinstall picks up where it left off).
#   --skip-template  Leave _template/whisper installed on the indexer.

set -u

WAZUH_PATH="${WAZUH_PATH:-/var/ossec}"
OSSEC_CONF="$WAZUH_PATH/etc/ossec.conf"
MARKER_BEGIN="whisper-integration:begin"
MARKER_END="whisper-integration:end"

PURGE=0
SKIP_TEMPLATE=0
INDEXER_URL_ARG="$(printf '%s' "${INDEXER_URL:-https://localhost:9200}" | tr -d '"')"
INDEXER_USER_ARG="${INDEXER_USERNAME:-admin}"
INDEXER_PASS_ARG="${INDEXER_PASSWORD:-}"

log()  { printf 'uninstall.sh: %s\n' "$*"; }
fail() { printf 'uninstall.sh: ERROR: %s\n' "$*" >&2; exit 1; }

# Pass the indexer credential to curl via stdin config so it never appears in `ps`.
idx_curl() {
    printf 'user = "%s:%s"\n' "$INDEXER_USER_ARG" "$INDEXER_PASS_ARG" | curl -sk -K - "$@"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --purge)         PURGE=1; shift ;;
        --skip-template) SKIP_TEMPLATE=1; shift ;;
        --indexer-url)   INDEXER_URL_ARG="$2"; shift 2 ;;
        --indexer-user)  INDEXER_USER_ARG="$2"; shift 2 ;;
        --indexer-pass)  INDEXER_PASS_ARG="$2"; shift 2 ;;
        *) fail "unknown argument: $1" ;;
    esac
done

[ "$(id -u)" = "0" ] || fail "must run as root"
[ -f "$OSSEC_CONF" ] || fail "$OSSEC_CONF not found"
mkdir -p "$WAZUH_PATH/tmp" || fail "cannot create $WAZUH_PATH/tmp"

# ---- 1. remove the marker-delimited <integration> block --------------------------------
if grep -q "$MARKER_BEGIN" "$OSSEC_CONF"; then
    log "removing the whisper <integration> block from ossec.conf"
    TMP_CONF="$WAZUH_PATH/tmp/ossec.conf.whisper.$$"
    sed "/$MARKER_BEGIN/,/$MARKER_END/d" "$OSSEC_CONF" > "$TMP_CONF" || fail "failed to render ossec.conf"
    grep -q "$MARKER_BEGIN" "$TMP_CONF" && fail "marker block survived the removal — aborting"
    cat "$TMP_CONF" > "$OSSEC_CONF"   # in place: keep the inode
    rm -f "$TMP_CONF"
else
    log "no whisper block in ossec.conf — nothing to remove there"
fi
# Re-assert ownership either way (a root:root ossec.conf breaks the manager).
chown root:wazuh "$OSSEC_CONF"
chmod 660 "$OSSEC_CONF"

# ---- 2. remove installed files -----------------------------------------------------------
log "removing integration files"
rm -f "$WAZUH_PATH/integrations/custom-whisper" "$WAZUH_PATH/integrations/custom-whisper.py" \
    "$WAZUH_PATH/integrations/whisper_client.py"
rm -f "$WAZUH_PATH/etc/rules/whisper_rules.xml" "$WAZUH_PATH/etc/rules/whisper_test_rules.xml"

if [ "$PURGE" = "1" ]; then
    log "purging key file + dedup cache"
    rm -f "$WAZUH_PATH/etc/whisper.key"
    rm -f "$WAZUH_PATH/var/whisper/dedup.db"*
    rmdir "$WAZUH_PATH/var/whisper" 2>/dev/null || true
fi

# ---- 3. remove the indexer template -------------------------------------------------------
if [ "$SKIP_TEMPLATE" = "0" ]; then
    log "removing _template/whisper from the indexer (best-effort)"
    idx_curl -o /dev/null -XDELETE "$INDEXER_URL_ARG/_template/whisper" >/dev/null 2>&1 \
        || log "WARNING: could not remove the template (indexer unreachable?) — remove it manually"
fi

# ---- 4. restart + verify (only lines written by THIS restart) ------------------------------
LOG="$WAZUH_PATH/logs/ossec.log"
LOG_LINES_BEFORE="$(wc -l < "$LOG" 2>/dev/null || echo 0)"
log "restarting the manager (~15s)"
"$WAZUH_PATH/bin/wazuh-control" restart >/dev/null 2>&1 || fail "wazuh-control restart failed"

sleep 6
if tail -n "+$((LOG_LINES_BEFORE + 1))" "$LOG" 2>/dev/null | grep -q "Enabling integration for: 'custom-whisper'"; then
    fail "integration STILL enabled after removal — inspect ossec.conf"
fi
log "OK — integration removed and manager restarted clean"