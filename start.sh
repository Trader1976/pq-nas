#!/usr/bin/env bash
#
# Usage:
#   source ./start.sh
# Then:
#   ./build/bin/pqnas_server
#
# What it does:
#   - Generates PQNAS env keys into .env.pqnas
#   - Loads /etc/pqnas/pqnas.env if present (system install env)
#   - Sets a STABLE origin/rp_id for Cloudflare named tunnel (no quick tunnel)
#   - Exports everything into your current shell
#

# Must be sourced, not executed (so exports persist)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  echo "ERROR: this script must be sourced (not executed)."
  echo "Run:"
  echo "  source ./start.sh"
  exit 1
fi

set -euo pipefail

ENV_FILE=".env.pqnas"

# ---- Stable public hostname (named tunnel) ----
# Change if you want a different hostname.
PQNAS_HOSTNAME_DEFAULT="pqnas-dev.pqnas-test.uk"

# ---- Local listen URL (what cloudflared forwards to) ----
LOCAL_URL_DEFAULT="http://127.0.0.1:8081"

echo "[*] Generating PQNAS keys -> $ENV_FILE"
./build/bin/pqnas_keygen > "$ENV_FILE"

# --- Load system install env (config + storage paths) if present ---
if [[ -f /etc/pqnas/pqnas.env ]]; then
  echo "[*] Loading system env: /etc/pqnas/pqnas.env"
  set -a
  # shellcheck disable=SC1091
  source /etc/pqnas/pqnas.env
  set +a
fi

# Determine hostname/origin/rp_id (prefer existing env, otherwise default)
PQNAS_HOSTNAME="${PQNAS_HOSTNAME:-$PQNAS_HOSTNAME_DEFAULT}"
export PQNAS_HOSTNAME

export PQNAS_ORIGIN="${PQNAS_ORIGIN:-https://$PQNAS_HOSTNAME}"
export PQNAS_RP_ID="${PQNAS_RP_ID:-$PQNAS_HOSTNAME}"

# Local URL (informational)
export PQNAS_LOCAL_URL="${PQNAS_LOCAL_URL:-$LOCAL_URL_DEFAULT}"

echo "[*] Writing stable origin env vars to $ENV_FILE"
cat >> "$ENV_FILE" <<EOF

export PQNAS_HOSTNAME="$PQNAS_HOSTNAME"
export PQNAS_ORIGIN="$PQNAS_ORIGIN"
export PQNAS_RP_ID="$PQNAS_RP_ID"
export PQNAS_LOCAL_URL="$PQNAS_LOCAL_URL"
EOF

echo "[*] Exporting variables into current shell (source $ENV_FILE)"
set -a
# shellcheck disable=SC1090
source "./$ENV_FILE"
set +a

# --- Dev overrides (must be AFTER /etc/pqnas/pqnas.env and .env.pqnas are sourced) ---
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

export PQNAS_AUTH_MODE="${PQNAS_AUTH_MODE:-v5}"
export PQNAS_STATIC_ROOT="${PQNAS_STATIC_ROOT:-$REPO_ROOT/server/src/static}"
export PQNAS_ADMIN_SETTINGS_PATH="${PQNAS_ADMIN_SETTINGS_PATH:-/etc/pqnas/admin_settings.json}"

echo "[*] Dev overrides:"
echo "    PQNAS_AUTH_MODE=$PQNAS_AUTH_MODE"
echo "    PQNAS_STATIC_ROOT=$PQNAS_STATIC_ROOT"
echo "    PQNAS_ADMIN_SETTINGS_PATH=$PQNAS_ADMIN_SETTINGS_PATH"

echo "[✓] Ready"
echo "    PQNAS_ORIGIN=$PQNAS_ORIGIN"
echo "    PQNAS_RP_ID=$PQNAS_RP_ID"
echo "    PQNAS_HOSTNAME=$PQNAS_HOSTNAME"
echo "    PQNAS_LOCAL_URL=$PQNAS_LOCAL_URL"
echo "./build/bin/pqnas_server"
echo "    PQNAS_DATA_ROOT=${PQNAS_DATA_ROOT:-<unset>}"

echo "Open local:  ${PQNAS_LOCAL_URL}/"
echo "Static test: ${PQNAS_LOCAL_URL}/static/theme.css"
echo "Open tunnel: ${PQNAS_ORIGIN}/"
echo "Static test: ${PQNAS_ORIGIN}/static/theme.css"

echo ""
echo "[i] NOTE:"
echo "    This script no longer starts Cloudflare Quick Tunnels."
echo "    Run your named tunnel separately, e.g.:"
echo "      cloudflared tunnel run pqnas-dev"
echo "    (or install it as a system service)."
