#!/bin/bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:8081}"

command -v curl >/dev/null || { echo "curl missing"; exit 1; }
command -v jq >/dev/null || { echo "jq missing"; exit 1; }
command -v qrencode >/dev/null || { echo "qrencode missing (sudo apt install qrencode)"; exit 1; }

resp="$(curl -sS -X POST "${BASE_URL}/api/v4/session")"

echo "$resp" | jq .

sid="$(echo "$resp" | jq -r '.sid')"
qr_uri="$(echo "$resp" | jq -r '.qr_uri')"

echo
echo "SID=$sid"
echo "QR_URI=$qr_uri"
echo

qrencode -o /tmp/pqnas_v4.png -l M -8 "$qr_uri"

if command -v xdg-open >/dev/null; then
  xdg-open /tmp/pqnas_v4.png >/dev/null 2>&1 || true
fi

echo "Wrote: /tmp/pqnas_v4.png"
echo "Poll: curl -s \"${BASE_URL}/api/v4/status?sid=${sid}\" | jq ."

#In your code, write down explicitly that PQ verify uses qgp_dsa87_verify returning 0 on success. You already lost time on the “rc semantics” once — this prevents it again.

#Also note the origin/tunnel mismatch as a known operational hazard.

#1) Generate keys into a file
#./build/bin/pqnas_keygen > .env.pqnas

#2) Load them into your current shell
#set -a
#source ./.env.pqnas
#set +a

#3) (Important) add your lib path + run
#export LD_LIBRARY_PATH="$PWD/build/bin${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
#./build/bin/pqnas_server

#4) Quick check that the env vars are really set

#In another terminal (or before running):
#env | grep -E '^PQNAS_(SERVER_PK_B64URL|SERVER_SK_B64URL|COOKIE_KEY_B64URL)='


#export PQNAS_ORIGIN="https://bag-findings-johnny-implied.trycloudflare.com"
#export PQNAS_RP_ID="bag-findings-johnny-implied.trycloudflare.com"
#export LD_LIBRARY_PATH="$PWD/build/bin${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
#./build/bin/pqnas_server

#Then generate a fresh session again:
#curl -sS -X POST http://127.0.0.1:8081/api/v4/session | jq -r '.qr_uri'
