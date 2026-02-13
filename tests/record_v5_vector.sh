#!/usr/bin/env bash
set -euo pipefail

# Always operate relative to repo root, regardless of where script is run from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

VEC="$REPO_ROOT/tests/v5_vectors/v5_vectors.json"
TMPDIR="${TMPDIR:-/tmp}"
BODY="$TMPDIR/v5_verify_body.json"

AUDIT_JSONL="/srv/pqnas/audit/pqnas_audit.jsonl"

########################################
# 1) latest captured /api/v5/verify body
########################################

if [[ ! -f "$AUDIT_JSONL" ]]; then
  echo "ERROR: audit log missing: $AUDIT_JSONL" >&2
  exit 3
fi

sudo jq -r '
  select(.event=="route.hit" and .f.path=="/api/v5/verify")
  | .f.verify_body_json
' "$AUDIT_JSONL" | tail -n 1 > "$BODY"

if [[ ! -s "$BODY" ]]; then
  echo "ERROR: audit did not yield a verify body" >&2
  exit 3
fi

# Extract origin from captured body (prefer signed_payload.origin; fallback to st payload origin)
CAPTURED_ORIGIN="$(
BODY_PATH="$BODY" python3 - <<'PY'
import os, json, base64
path = os.environ["BODY_PATH"]
body = json.load(open(path,"r",encoding="utf-8"))

sp = body.get("signed_payload", {})
if isinstance(sp, dict) and isinstance(sp.get("origin"), str) and sp["origin"]:
    print(sp["origin"])
    raise SystemExit(0)

st = body["st"]
payload = st.split(".")[1]
payload += "=" * (-len(payload) % 4)
p = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
o = p.get("origin","")
if not isinstance(o,str) or not o:
    raise SystemExit("missing origin in body")
print(o)
PY
)"

########################################
# 2) find the pqnas_server PID that matches CAPTURED_ORIGIN
########################################

PIDS_STR="$(pidof pqnas_server || true)"
if [[ -z "$PIDS_STR" ]]; then
  echo "ERROR: pqnas_server not running" >&2
  exit 2
fi

PID=""
for p in $PIDS_STR; do
  ORIGIN_P="$(
    sudo tr '\0' '\n' <"/proc/$p/environ" 2>/dev/null \
      | sed -n 's/^PQNAS_ORIGIN=//p' | head -n1
  )"
  if [[ "$ORIGIN_P" == "$CAPTURED_ORIGIN" ]]; then
    PID="$p"
    break
  fi
done

if [[ -z "$PID" ]]; then
  echo "ERROR: could not find a pqnas_server PID whose PQNAS_ORIGIN matches the captured verify body origin." >&2
  echo "  captured origin: $CAPTURED_ORIGIN" >&2
  echo "  running pids:    $PIDS_STR" >&2
  echo "Dumping PQNAS_ORIGIN per PID:" >&2
  for p in $PIDS_STR; do
    o="$(sudo tr '\0' '\n' </proc/$p/environ 2>/dev/null | sed -n 's/^PQNAS_ORIGIN=//p' | head -n1 || true)"
    pk="$(sudo tr '\0' '\n' </proc/$p/environ 2>/dev/null | sed -n 's/^PQNAS_SERVER_PK_B64URL=//p' | head -n1 || true)"
    echo "  pid=$p origin=$o pk=$pk" >&2
  done
  exit 2
fi

########################################
# 3) runtime pk from that PID (source of truth)
########################################

PK_PROC="$(
sudo tr '\0' '\n' <"/proc/$PID/environ" \
  | sed -n 's/^PQNAS_SERVER_PK_B64URL=//p' \
  | head -n1
)"

if [[ -z "${PK_PROC}" ]]; then
  echo "ERROR: could not read PQNAS_SERVER_PK_B64URL from /proc/$PID/environ" >&2
  exit 2
fi

########################################
# 4) compute now_unix_sec midpoint from st payload
########################################

NOW_UNIX_SEC="$(
BODY_PATH="$BODY" python3 - <<'PY'
import os, json, base64
path = os.environ["BODY_PATH"]
body = json.load(open(path,"r",encoding="utf-8"))
st = body["st"]
payload = st.split(".")[1]
payload += "=" * (-len(payload) % 4)
p = json.loads(base64.urlsafe_b64decode(payload).decode("utf-8"))
iat = p.get("iat", p.get("issued_at"))
exp = p.get("exp", p.get("expires_at"))
if not isinstance(iat,int) or not isinstance(exp,int):
    raise SystemExit("missing iat/exp")
now = (iat+exp)//2
if not (iat <= now <= exp):
    raise SystemExit("now not in range")
print(now)
PY
)"

########################################
# Ensure vectors file exists
########################################

if [[ ! -f "$VEC" ]]; then
  echo "ERROR: vectors file missing: $VEC" >&2
  exit 4
fi

########################################
# 5) update vectors by CASE NAME (happy_path)
########################################

jq --arg pk "$PK_PROC" \
   --arg body "$(cat "$BODY")" \
   --argjson now "$NOW_UNIX_SEC" \
   '
   .server_pk_b64 = $pk
   | .now_unix_sec = $now
   | .enforce_origin_rp = false
   | .expected_origin = ""
   | .expected_rp_id = ""
   | (.cases[] | select(.name=="happy_path")) |=
       (.expect_ok = true
        | .verify_body_json = $body
        | .expect_k = "")   # will fill next
   ' "$VEC" > "$TMPDIR/v5_vectors.json"

mv "$TMPDIR/v5_vectors.json" "$VEC"

########################################
# 6) derive expect_k from captured body itself (stable)
########################################

K_FROM_BODY="$(
BODY_PATH="$BODY" python3 - <<'PY'
import os, json
path = os.environ["BODY_PATH"]
body = json.load(open(path,"r",encoding="utf-8"))
sp = body.get("signed_payload", {}) if isinstance(body.get("signed_payload"), dict) else {}
k = (sp.get("st_hash") or sp.get("k") or body.get("k") or "")
if not isinstance(k,str) or not k:
    raise SystemExit("missing signed_payload.st_hash / k")
print(k)
PY
)"

jq --arg k "$K_FROM_BODY" '
  (.cases[] | select(.name=="happy_path") | .expect_k) = $k
' "$VEC" > "$TMPDIR/v5_vectors.json" && mv "$TMPDIR/v5_vectors.json" "$VEC"

########################################
# 7) final run (must pass)
########################################

echo "[record_v5_vector] Updated $VEC"
echo "  captured_origin=$CAPTURED_ORIGIN"
echo "  picked_pid=$PID"
echo "  server_pk_b64=$PK_PROC"
echo "  now_unix_sec=$NOW_UNIX_SEC"
echo "  expect_k=$K_FROM_BODY"

"$REPO_ROOT/build/bin/verify_v5_vectors" "$VEC"
