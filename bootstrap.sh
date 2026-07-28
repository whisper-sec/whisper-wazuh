#!/bin/sh
# bootstrap.sh — one-line installer for the whisper-wazuh integration.
#
# Downloads the latest release bundle and runs its install.sh with the args you pass. Run AS
# ROOT on a Wazuh manager:
#
#   curl -sSL https://raw.githubusercontent.com/whisper-sec/whisper-wazuh/main/bootstrap.sh \
#     | sudo sh -s -- --group sshd --api-key-file /path/to/your-whisper-key.txt
#
# Pin a version:            WHISPER_WAZUH_VERSION=v1.0.0 (env)
# Use a mirror / local file: WHISPER_WAZUH_URL=https://…/whisper-wazuh.tar.gz (env)
#
# Prefer to inspect before running as root? Download the tarball from the Releases page, unpack
# it, read install.sh, and run it yourself — this script does exactly that, nothing more.
set -eu

REPO="whisper-sec/whisper-wazuh"
VERSION="${WHISPER_WAZUH_VERSION:-latest}"

if [ -n "${WHISPER_WAZUH_URL:-}" ]; then
    URL="$WHISPER_WAZUH_URL"
elif [ "$VERSION" = "latest" ]; then
    URL="https://github.com/$REPO/releases/latest/download/whisper-wazuh.tar.gz"
else
    URL="https://github.com/$REPO/releases/download/$VERSION/whisper-wazuh-${VERSION#v}.tar.gz"
fi

command -v curl >/dev/null 2>&1 || { echo "bootstrap: curl is required" >&2; exit 1; }
command -v tar  >/dev/null 2>&1 || { echo "bootstrap: tar is required" >&2; exit 1; }

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

echo "bootstrap: downloading $URL"
# download to a file first (a piped `curl | tar` hides curl's exit behind tar's)
curl -fsSL "$URL" -o "$TMP/bundle.tar.gz" || { echo "bootstrap: download failed ($URL)" >&2; exit 1; }
tar xzf "$TMP/bundle.tar.gz" -C "$TMP" || { echo "bootstrap: extract failed" >&2; exit 1; }

DIR="$(find "$TMP" -maxdepth 1 -type d -name 'whisper-wazuh-*' | head -n1)"
[ -n "$DIR" ] && [ -f "$DIR/install.sh" ] || { echo "bootstrap: install.sh not found in the bundle" >&2; exit 1; }

echo "bootstrap: running install.sh $*"
sh "$DIR/install.sh" "$@"