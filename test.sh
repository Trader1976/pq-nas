#!/usr/bin/env bash
set -euo pipefail

ORIGIN="${ORIGIN:-https://statutes-anchor-friendship-finance.trycloudflare.com}"
COOKIES="${COOKIES:-/tmp/pqnas.cookies}"
WAIT_SEC="${WAIT_SEC:-20}"

urlenc() {
  python3 - <<'PY' "$1"
import urllib.parse,sys
print(urllib.parse.quote(sys.argv[1], safe=""))
PY
}

echo "[*] Creating session..."
S="$(curl -fsS "$ORIGIN/api/v5/session")"

echo
echo "===== SESSION ====="
echo "$S" | jq

SID="$(echo "$S" | jq -r .sid)"
K="$(echo "$S" | jq -r .k)"
QR="$(echo "$S" | jq -r .qr_svg)"

KENC="$(urlenc "$K")"

echo
echo "SID = $SID"
echo "K   = $K"
echo
echo "👉 OPEN THIS QR:"
echo "$ORIGIN$QR"
echo

echo "[*] Status before scan..."
curl -fsS "$ORIGIN/api/v5/status?k=$KENC" | jq
echo

echo "[*] Waiting ${WAIT_SEC}s so you can scan..."
for i in $(seq 1 "$WAIT_SEC"); do
  printf "  %2d/%d\r" "$i" "$WAIT_SEC"
  sleep 1
done
echo
echo

echo "[*] Checking status after scan..."
curl -fsS "$ORIGIN/api/v5/status?k=$KENC" | jq
echo

echo "[*] Consuming approval (setting cookie)..."
rm -f "$COOKIES"
curl -fsS -c "$COOKIES" \
  -X POST "$ORIGIN/api/v5/consume" \
  -H 'Content-Type: application/json' \
  --data-binary "$(jq -n --arg k "$K" '{k:$k}')" | jq
echo

echo "[*] Calling /api/v4/me with cookie..."
curl -fsS -b "$COOKIES" "$ORIGIN/api/v4/me" | jq
echo
echo "[✓] Done."
