#!/bin/sh
# install.sh — install the custom-whisper integration on a Wazuh manager (4.x).
#
# Run AS ROOT on the manager (package-based VM or inside the manager container).
# Every step below was verified by hand on wazuh/wazuh-manager:4.14.5 before being
# codified here (issues #13-#18); the mapping spec (docs/whisper-to-wazuh-mapping.md)
# documents the contracts each step honors.
#
# Ordering & safety: the indexer template is PUT FIRST, so an unreachable indexer aborts
# BEFORE any manager file is touched. The ossec.conf write is guarded by a rollback trap
# that restores the timestamped backup on any failure mid-write. Re-running is drift-safe:
# an existing managed block is removed and re-rendered with the current flags.
#
# Usage:
#   install.sh [--group <csv>] [--dev] [--skip-template] [--refresh-index]
#              [--indexer-url URL] [--indexer-user USER] [--indexer-pass PASS]
#
#   --group <csv>     Rule groups that trigger enrichment (default: sshd). NEVER level-only,
#                     and never a group the enrichment alerts themselves carry (loop guard).
#   --dev             Dev mode: also install whisper_test_rules.xml and add the whisper_test
#                     group to the trigger filter (domain-TC mechanism).
#   --skip-template   Skip the indexer template PUT (install _template/whisper yourself
#                     before the first enrichment alert — mapping spec section 4.3).
#   --refresh-index   DEV ONLY (requires --dev): delete the current day's alerts index so it
#                     re-creates with the whisper template types. DESTRUCTIVE to today's alerts.
#   --indexer-*       Where to PUT the template. Defaults: $INDEXER_URL / $INDEXER_USERNAME /
#                     $INDEXER_PASSWORD (set in the official manager container), else
#                     https://localhost:9200. The password is passed to curl via stdin config
#                     (-K -), never on the command line.
#
# Secrets: the Whisper API key is NEVER placed in ossec.conf (it would appear in the
# integratord child's /proc cmdline). The key resolves env -> /var/ossec/etc/whisper.key
# -> argv; this installer creates the key file with a placeholder if absent.

set -u

WAZUH_PATH="${WAZUH_PATH:-/var/ossec}"
SRC_DIR="$(cd "$(dirname "$0")" && pwd -P)"
OSSEC_CONF="$WAZUH_PATH/etc/ossec.conf"
KEY_FILE="$WAZUH_PATH/etc/whisper.key"
PLACEHOLDER="WHISPER_API_KEY_PLACEHOLDER"
MARKER_BEGIN="whisper-integration:begin"
MARKER_END="whisper-integration:end"

GROUPS_CSV="sshd"
DEV_MODE=0
SKIP_TEMPLATE=0
REFRESH_INDEX=0
INDEXER_URL_ARG="$(printf '%s' "${INDEXER_URL:-https://localhost:9200}" | tr -d '"')"
INDEXER_USER_ARG="${INDEXER_USERNAME:-admin}"
INDEXER_PASS_ARG="${INDEXER_PASSWORD:-}"

# Rollback state (set once the ossec.conf backup exists and the write is in flight).
ROLLBACK_CONF=""

log()  { printf 'install.sh: %s\n' "$*"; }
fail() { printf 'install.sh: ERROR: %s\n' "$*" >&2; exit 1; }

cleanup() {
    # Restore ossec.conf only if we died with a write in flight (backup captured, not disarmed).
    if [ -n "$ROLLBACK_CONF" ] && [ -f "$ROLLBACK_CONF" ]; then
        printf 'install.sh: rolling back ossec.conf from %s\n' "$ROLLBACK_CONF" >&2
        cat "$ROLLBACK_CONF" > "$OSSEC_CONF" 2>/dev/null
        chown root:wazuh "$OSSEC_CONF" 2>/dev/null
        chmod 660 "$OSSEC_CONF" 2>/dev/null
    fi
}
trap cleanup EXIT INT TERM

# Pass the indexer credential to curl via stdin config so it never appears in `ps`.
idx_curl() {
    printf 'user = "%s:%s"\n' "$INDEXER_USER_ARG" "$INDEXER_PASS_ARG" | curl -sk -K - "$@"
}

while [ $# -gt 0 ]; do
    case "$1" in
        --group)         GROUPS_CSV="$2"; shift 2 ;;
        --dev)           DEV_MODE=1; shift ;;
        --skip-template) SKIP_TEMPLATE=1; shift ;;
        --refresh-index) REFRESH_INDEX=1; shift ;;
        --indexer-url)   INDEXER_URL_ARG="$2"; shift 2 ;;
        --indexer-user)  INDEXER_USER_ARG="$2"; shift 2 ;;
        --indexer-pass)  INDEXER_PASS_ARG="$2"; shift 2 ;;
        *) fail "unknown argument: $1" ;;
    esac
done

# ---- preconditions -----------------------------------------------------------------
[ "$(id -u)" = "0" ] || fail "must run as root (owns $WAZUH_PATH files)"
[ -x "$WAZUH_PATH/bin/wazuh-control" ] || fail "wazuh-control not found under $WAZUH_PATH"
[ -f "$OSSEC_CONF" ] || fail "$OSSEC_CONF not found"
[ "$REFRESH_INDEX" = "1" ] && [ "$DEV_MODE" = "0" ] && fail "--refresh-index requires --dev (destructive)"

REQUIRED="custom-whisper custom-whisper.py whisper_client.py whisper_rules.xml whisper-template.json"
[ "$DEV_MODE" = "1" ] && REQUIRED="$REQUIRED whisper_test_rules.xml"
for f in $REQUIRED; do
    [ -f "$SRC_DIR/$f" ] || fail "source file missing: $SRC_DIR/$f"
done
mkdir -p "$WAZUH_PATH/tmp" || fail "cannot create $WAZUH_PATH/tmp"

# Loop guard: the trigger filter must never watch a group the enrichment alerts carry
# (mapping section 8; the emitted rules sit in whisper,whisper_enrichment,whisper_<verdict>).
EMITTED_GROUPS="whisper whisper_enrichment whisper_known_bad whisper_suspicious whisper_known_good whisper_unknown whisper_c2"
for token in $(printf '%s' "$GROUPS_CSV" | tr ',' ' '); do
    for emitted in $EMITTED_GROUPS; do
        [ "$token" = "$emitted" ] && fail "--group '$token' would create a feedback loop (enrichment alerts carry that group)"
    done
done

FILTER_GROUPS="$GROUPS_CSV"
[ "$DEV_MODE" = "1" ] && FILTER_GROUPS="$GROUPS_CSV,whisper_test"

# ---- 0. indexer template FIRST (abort before touching the manager) -------------------
if [ "$SKIP_TEMPLATE" = "1" ]; then
    log "skipping indexer template (--skip-template) — install _template/whisper yourself"
else
    log "PUT _template/whisper -> $INDEXER_URL_ARG (legacy template, order 1)"
    CODE="$(idx_curl -o /dev/null -w '%{http_code}' -XPUT "$INDEXER_URL_ARG/_template/whisper" \
        -H 'Content-Type: application/json' -d @"$SRC_DIR/whisper-template.json")" \
        || fail "indexer unreachable at $INDEXER_URL_ARG (use --indexer-url or --skip-template)"
    case "$CODE" in
        200|201) log "template acknowledged (HTTP $CODE)" ;;
        *) fail "template PUT returned HTTP $CODE" ;;
    esac
    if [ "$REFRESH_INDEX" = "1" ]; then
        TODAY_INDEX="wazuh-alerts-4.x-$(date +%Y.%m.%d)"
        log "dev refresh: deleting $TODAY_INDEX so it re-creates with whisper types"
        idx_curl -o /dev/null -XDELETE "$INDEXER_URL_ARG/$TODAY_INDEX" >/dev/null 2>&1 || true
    fi
fi

# ---- 1. integration script + wrapper (750 root:wazuh) --------------------------------
log "installing integration script -> $WAZUH_PATH/integrations/"
cp "$SRC_DIR/custom-whisper" "$SRC_DIR/custom-whisper.py" "$SRC_DIR/whisper_client.py" "$WAZUH_PATH/integrations/" \
    || fail "cp integration script failed"
chown root:wazuh "$WAZUH_PATH/integrations/custom-whisper" "$WAZUH_PATH/integrations/custom-whisper.py" \
    "$WAZUH_PATH/integrations/whisper_client.py"
chmod 750 "$WAZUH_PATH/integrations/custom-whisper" "$WAZUH_PATH/integrations/custom-whisper.py"
chmod 640 "$WAZUH_PATH/integrations/whisper_client.py"  # imported, not executed

# ---- 2. rules (660 root:wazuh) --------------------------------------------------------
log "installing whisper_rules.xml -> $WAZUH_PATH/etc/rules/"
cp "$SRC_DIR/whisper_rules.xml" "$WAZUH_PATH/etc/rules/whisper_rules.xml" || fail "cp whisper_rules.xml failed"
chown root:wazuh "$WAZUH_PATH/etc/rules/whisper_rules.xml"
chmod 660 "$WAZUH_PATH/etc/rules/whisper_rules.xml"
if [ "$DEV_MODE" = "1" ]; then
    log "dev mode: installing whisper_test_rules.xml (domain-TC trigger)"
    cp "$SRC_DIR/whisper_test_rules.xml" "$WAZUH_PATH/etc/rules/whisper_test_rules.xml" || fail "cp whisper_test_rules.xml failed"
    chown root:wazuh "$WAZUH_PATH/etc/rules/whisper_test_rules.xml"
    chmod 660 "$WAZUH_PATH/etc/rules/whisper_test_rules.xml"
fi

# ---- 3. key file (640 root:wazuh; placeholder never counts as a key) ------------------
if [ ! -f "$KEY_FILE" ]; then
    log "creating $KEY_FILE with placeholder (put your real Whisper API key in it)"
    printf '%s\n' "$PLACEHOLDER" > "$KEY_FILE" || fail "cannot write $KEY_FILE"
fi
chown root:wazuh "$KEY_FILE"
chmod 640 "$KEY_FILE"

# ---- 3b. dedup cache dir (connector runs as the wazuh user; /var/ossec/var is root-owned) --
DEDUP_DIR="$WAZUH_PATH/var/whisper"
LOG_OWNER="$(stat -c '%U:%G' "$WAZUH_PATH/logs" 2>/dev/null || echo 'wazuh:wazuh')"
log "creating dedup cache dir $DEDUP_DIR ($LOG_OWNER, 0770)"
mkdir -p "$DEDUP_DIR" || fail "cannot create $DEDUP_DIR"
chown "$LOG_OWNER" "$DEDUP_DIR" 2>/dev/null || chown wazuh:wazuh "$DEDUP_DIR"
chmod 770 "$DEDUP_DIR"

# ---- 4. ossec.conf: back up, then remove-any-old-block + re-render (drift-safe) -------
BACKUP="$OSSEC_CONF.pre-whisper.$(date +%Y%m%d%H%M%S)"
log "backing up ossec.conf -> $BACKUP"
cp -p "$OSSEC_CONF" "$BACKUP" || fail "cannot back up ossec.conf"

TMP_CONF="$WAZUH_PATH/tmp/ossec.conf.whisper.$$"
# Strip any existing managed block, then insert a fresh one before the FIRST standalone
# </ossec_config> line (anchored so the tag inside a comment/shared line can't match).
sed "/$MARKER_BEGIN/,/$MARKER_END/d" "$OSSEC_CONF" | awk -v groups="$FILTER_GROUPS" '
    /^[[:space:]]*<\/ossec_config>[[:space:]]*$/ && !ins {
        print "  <!-- whisper-integration:begin (managed by install.sh - do not edit inside) -->"
        print "  <integration>"
        print "    <name>custom-whisper</name>"
        print "    <group>" groups "</group>"
        print "    <alert_format>json</alert_format>"
        print "  </integration>"
        print "  <!-- whisper-integration:end -->"
        ins = 1
    }
    { print }
    END { if (!ins) exit 3 }
' > "$TMP_CONF" || fail "no standalone </ossec_config> line in ossec.conf — patch aborted (nothing changed)"
grep -q "$MARKER_BEGIN" "$TMP_CONF" || fail "patch render failed"

# Arm rollback around the in-place write (a truncated ossec.conf breaks the manager).
ROLLBACK_CONF="$BACKUP"
cat "$TMP_CONF" > "$OSSEC_CONF" || fail "failed writing ossec.conf"
chown root:wazuh "$OSSEC_CONF"
chmod 660 "$OSSEC_CONF"
ROLLBACK_CONF=""   # write succeeded — disarm rollback
rm -f "$TMP_CONF"
log "ossec.conf patched (trigger groups: $FILTER_GROUPS)"

# ---- 5. restart + verify (only lines written by THIS restart) -------------------------
LOG="$WAZUH_PATH/logs/ossec.log"
LOG_LINES_BEFORE="$(wc -l < "$LOG" 2>/dev/null || echo 0)"
log "restarting the manager (~15s)"
"$WAZUH_PATH/bin/wazuh-control" restart >/dev/null 2>&1 || fail "wazuh-control restart failed — check $LOG (backup: $BACKUP)"

log "verifying integratord enabled the integration"
tries=0
while [ $tries -lt 15 ]; do
    if tail -n "+$((LOG_LINES_BEFORE + 1))" "$LOG" 2>/dev/null | grep -q "Enabling integration for: 'custom-whisper'"; then
        log "OK — integratord: Enabling integration for: 'custom-whisper'"
        log "install complete. Trigger groups: $FILTER_GROUPS"
        if grep -q "$PLACEHOLDER" "$KEY_FILE" 2>/dev/null; then
            log "NOTE: $KEY_FILE still holds the placeholder — enrichment will fail auth until you put a real key in it (640 root:wazuh)"
        fi
        exit 0
    fi
    tries=$((tries + 1))
    sleep 2
done
fail "integration not enabled after restart — check $LOG (backup: $BACKUP)"