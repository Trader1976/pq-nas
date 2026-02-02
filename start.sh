#!/usr/bin/env bash
#
# Usage:
#   source ./setup_env.sh
# Then:
#   ./build/bin/pqnas_server
#
# What it does:
#   - Generates PQNAS env keys into .env.pqnas
#   - Starts a NEW Cloudflare Quick Tunnel to http://127.0.0.1:8081
#   - Extracts the public https://*.trycloudflare.com URL from cloudflared logs
#   - Appends PQNAS_ORIGIN / PQNAS_RP_ID exports to .env.pqnas
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
TUNNEL_URL="http://127.0.0.1:8081"
LOG_FILE="/tmp/pqnas_cloudflared_quicktunnel.log"

# If we previously started cloudflared from this shell, stop it first
if [[ -n "${PQNAS_CLOUDFLARED_PID:-}" ]]; then
  if kill -0 "$PQNAS_CLOUDFLARED_PID" 2>/dev/null; then
    echo "[*] Stopping previous cloudflared (pid=$PQNAS_CLOUDFLARED_PID)"
    kill "$PQNAS_CLOUDFLARED_PID" 2>/dev/null || true
  fi
  unset PQNAS_CLOUDFLARED_PID
fi

echo "[*] Generating PQNAS keys -> $ENV_FILE"
./build/bin/pqnas_keygen > "$ENV_FILE"

echo "[*] Starting Cloudflare Quick Tunnel -> $TUNNEL_URL"
rm -f "$LOG_FILE"

# Start cloudflared in background and capture logs
# (We keep the process running; the URL stays valid only while it runs.)
cloudflared tunnel --url "$TUNNEL_URL" --loglevel info 2>&1 | tee "$LOG_FILE" >/dev/null &
PQNAS_CLOUDFLARED_PID=$!
export PQNAS_CLOUDFLARED_PID

# Extract URL from logs (wait up to ~20 seconds)
ORIGIN=""
for _ in $(seq 1 200); do
  ORIGIN="$(grep -Eo 'https://[a-zA-Z0-9-]+\.trycloudflare\.com' "$LOG_FILE" | head -n1 || true)"
  if [[ -n "$ORIGIN" ]]; then break; fi
  sleep 0.1
done

if [[ -z "$ORIGIN" ]]; then
  echo "ERROR: Could not detect trycloudflare URL from cloudflared output." >&2
  echo "Log file: $LOG_FILE" >&2
  echo "cloudflared pid: $PQNAS_CLOUDFLARED_PID" >&2
  return 1
fi

RP_ID="${ORIGIN#https://}"

echo "[*] Writing tunnel env vars to $ENV_FILE"
cat >> "$ENV_FILE" <<EOF

export PQNAS_ORIGIN="$ORIGIN"
export PQNAS_RP_ID="$RP_ID"
EOF
# --- Load system install env (config + storage paths) if present ---
if [[ -f /etc/pqnas/pqnas.env ]]; then
  echo "[*] Loading system env: /etc/pqnas/pqnas.env"
  set -a
  # shellcheck disable=SC1091
  source /etc/pqnas/pqnas.env
  set +a
fi

echo "[*] Exporting variables into current shell (source $ENV_FILE)"
set -a
# shellcheck disable=SC1090
source "./$ENV_FILE"
set +a

echo "[✓] Ready"
echo "    PQNAS_ORIGIN=$PQNAS_ORIGIN"
echo "    PQNAS_RP_ID=$PQNAS_RP_ID"
echo "    cloudflared pid=$PQNAS_CLOUDFLARED_PID"
echo "    cloudflared log=$LOG_FILE"
echo "./build/bin/pqnas_server"
echo "    PQNAS_ADMIN_SETTINGS_PATH=${PQNAS_ADMIN_SETTINGS_PATH:-<unset>}"

