#!/usr/bin/env bash
#
# dev-init.sh — initialize local domain access for the whisper-wazuh dev stack.
#
# Idempotent. Does the following:
#   1. Ensures the Wazuh indexer TLS certs exist (generates them if missing).
#   2. Issues a Traefik wildcard cert for *.whisper-wazuh-dev.localhost, signed
#      by the existing Wazuh root CA.
#   3. Adds the dev domains to /etc/hosts            (needs sudo).
#   4. Trusts the Wazuh root CA so browsers/curl don't warn (needs sudo).
#
# After running, bring the stack up with:
#   docker compose -f docker-compose.yml -f docker-compose.traefik.yml up -d
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STACK_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CERT_DIR="$STACK_DIR/config/certs"   # all dev-stack certs (Wazuh set + Traefik wildcard) live here

WILDCARD="*.whisper-wazuh-dev.localhost"
DOMAINS=(
  "dashboard.whisper-wazuh-dev.localhost"
  "manager.whisper-wazuh-dev.localhost"
  "indexer.whisper-wazuh-dev.localhost"
)

log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }

# --- 1. Wazuh indexer certs ---------------------------------------------------
if [[ ! -f "$CERT_DIR/root-ca.pem" || ! -f "$CERT_DIR/root-ca.key" ]]; then
  log "Wazuh root CA not found — generating indexer certs first..."
  ( cd "$STACK_DIR" && docker compose -f generate-indexer-certs.yml run --rm generator )
fi
[[ -f "$CERT_DIR/root-ca.pem" && -f "$CERT_DIR/root-ca.key" ]] || {
  warn "Root CA still missing at $CERT_DIR — cannot continue."; exit 1; }

# --- 2. Traefik wildcard cert (signed by the Wazuh root CA) -------------------
log "Issuing Traefik wildcard cert for $WILDCARD"
mkdir -p "$CERT_DIR"
SAN_CNF="$(mktemp)"
trap 'rm -f "$SAN_CNF" "$SAN_CNF.csr"' EXIT
{
  echo "[req]"
  echo "distinguished_name = dn"
  echo "req_extensions = v3_req"
  echo "prompt = no"
  echo "[dn]"
  echo "CN = $WILDCARD"
  echo "[v3_req]"
  echo "basicConstraints = CA:FALSE"
  echo "keyUsage = digitalSignature, keyEncipherment"
  echo "extendedKeyUsage = serverAuth"
  echo "subjectAltName = DNS:$WILDCARD"
} > "$SAN_CNF"

openssl genrsa -out "$CERT_DIR/wildcard.key" 2048 2>/dev/null
openssl req -new -key "$CERT_DIR/wildcard.key" -out "$SAN_CNF.csr" -config "$SAN_CNF"
openssl x509 -req -in "$SAN_CNF.csr" \
  -CA "$CERT_DIR/root-ca.pem" -CAkey "$CERT_DIR/root-ca.key" -CAcreateserial \
  -out "$CERT_DIR/wildcard.crt" -days 825 -sha256 \
  -extfile "$SAN_CNF" -extensions v3_req 2>/dev/null
chmod 644 "$CERT_DIR/wildcard.crt" "$CERT_DIR/wildcard.key"
log "Wrote $CERT_DIR/wildcard.{crt,key}"

# --- 3. /etc/hosts ------------------------------------------------------------
HOSTS_MARK="# whisper-wazuh dev domains"
if grep -q "${DOMAINS[0]}" /etc/hosts 2>/dev/null; then
  log "/etc/hosts already has the dev domains — skipping."
else
  log "Adding dev domains to /etc/hosts (sudo)..."
  printf '%s\n127.0.0.1 %s\n' "$HOSTS_MARK" "${DOMAINS[*]}" | sudo tee -a /etc/hosts >/dev/null
fi

# --- 4. Trust the Wazuh root CA ----------------------------------------------
case "$(uname -s)" in
  Darwin)
    log "Trusting Wazuh root CA in the macOS System keychain (sudo)..."
    sudo security add-trusted-cert -d -r trustRoot \
      -k /Library/Keychains/System.keychain "$CERT_DIR/root-ca.pem"
    ;;
  Linux)
    if command -v update-ca-certificates >/dev/null 2>&1; then
      log "Trusting Wazuh root CA via update-ca-certificates (sudo)..."
      sudo cp "$CERT_DIR/root-ca.pem" /usr/local/share/ca-certificates/whisper-wazuh-root.crt
      sudo update-ca-certificates >/dev/null
    else
      warn "Unknown trust store — import $CERT_DIR/root-ca.pem manually."
    fi
    ;;
  *) warn "Unsupported OS — import $CERT_DIR/root-ca.pem into your trust store manually." ;;
esac

# --- Done --------------------------------------------------------------------
echo
log "Done. Bring the stack up with:"
echo "    cd \"$STACK_DIR\""
echo "    docker compose -f docker-compose.yml -f docker-compose.traefik.yml up -d"
echo
log "Then browse to:"
for d in "${DOMAINS[@]}"; do echo "    https://$d"; done