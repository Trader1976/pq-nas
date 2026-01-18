#/bin/bash
resp="$(curl -sS -X POST http://127.0.0.1:8081/api/v4/session)"
echo "$resp" | jq .
qr_uri="$(echo "$resp" | jq -r '.qr_uri')"
echo "$qr_uri"
qrencode -o /tmp/pqnas_v4.png -l M -8 "$qr_uri"
xdg-open /tmp/pqnas_v4.png

