#!/usr/bin/env bash
set -euo pipefail

# ==============================
# J-Secure Cloud — GRAND TEST
# ==============================
BASE="${BASE:-http://127.0.0.1:8081}"

echo "=============================="
echo "J-Secure Cloud — GRAND TEST"
echo "BASE=$BASE"
echo "================================"

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "❌ missing: $1"; exit 1; }; }
need_cmd curl
need_cmd jq
need_cmd wc
need_cmd dd
need_cmd ls
need_cmd awk
need_cmd tr
need_cmd head

ok() { echo "✅ $1"; }
fail() { echo "❌ $1"; exit 1; }

# Read MAX_UPLOAD_BYTES from env (same as server), fallback 10 MiB.
MAX_UPLOAD_BYTES="${MAX_UPLOAD_BYTES:-10485760}"

# Build a "too large" size: MAX_UPLOAD_BYTES + 1 MiB (minimum 2 MiB)
B5_OVER=$((MAX_UPLOAD_BYTES + 1024*1024))
if (( B5_OVER < 2097152 )); then
  B5_OVER=2097152
fi

# Convert bytes to dd params (MiB blocks)
# We'll create ceil(B5_OVER / 1MiB) MiB to guarantee it's > max.
B5_MIB=$(( (B5_OVER + 1024*1024 - 1) / (1024*1024) ))

tmpdir="/tmp"
REG_JSON="$tmpdir/jsc_reg.json"
LOGIN_JSON="$tmpdir/jsc_login.json"
REG2_JSON="$tmpdir/jsc_reg2.json"
BAD_JSON="$tmpdir/jsc_bad.json"
LIST_NOAUTH_JSON="$tmpdir/jsc_list_noauth.json"
UP_JSON="$tmpdir/jsc_up.json"
DEL_JSON="$tmpdir/jsc_del.json"
B5_JSON="$tmpdir/jsc_b5.json"

# --- 0) CORS PRE-FLIGHT
echo "0) CORS PRE-FLIGHT (OPTIONS)"
CORS_CODE="$(curl -sS -o /dev/null -w "%{http_code}" -X OPTIONS \
  -H "Origin: http://localhost:8080" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: content-type, authorization" \
  "$BASE/api/auth/login")"
[[ "$CORS_CODE" == "200" || "$CORS_CODE" == "204" ]] \
  && ok "CORS preflight (code=$CORS_CODE)" \
  || fail "CORS attendu 200/204, reçu $CORS_CODE"
echo

# --- 1) HEALTH
echo "1) HEALTH (200 + JSON)"
HEALTH_JSON="$(curl -sS "$BASE/api/health")"
echo "$HEALTH_JSON" | jq -e '.status' >/dev/null || fail "health json invalide"
[[ "$(echo "$HEALTH_JSON" | jq -r '.status')" == "ok" ]] && ok "health ok" || fail "health status != ok"
echo

# --- 2) REGISTER / LOGIN
echo "2) REGISTER / LOGIN (user principal)"
TS="$(date +%s)"
EMAIL="grandtest_${TS}@local.dev"
PASS="Passw0rd!${TS}"

REG_CODE="$(curl -sS -o "$REG_JSON" -w "%{http_code}" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" \
  "$BASE/api/auth/register")"
[[ "$REG_CODE" == "200" ]] && ok "register ok" || { cat "$REG_JSON"; fail "register code=$REG_CODE"; }

LOGIN_CODE="$(curl -sS -o "$LOGIN_JSON" -w "%{http_code}" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" \
  "$BASE/api/auth/login")"
[[ "$LOGIN_CODE" == "200" ]] && ok "login ok (token obtenu)" || { cat "$LOGIN_JSON"; fail "login code=$LOGIN_CODE"; }

TOKEN="$(jq -r '.token' "$LOGIN_JSON")"
[[ "$TOKEN" != "null" && -n "$TOKEN" ]] || { cat "$LOGIN_JSON"; fail "token manquant"; }
HDR_AUTH=(-H "Authorization: Bearer $TOKEN")
echo

# --- 3) REGISTER CONFLICT -> 409
echo "3) REGISTER CONFLICT -> 409 + JSON"
REG2_CODE="$(curl -sS -o "$REG2_JSON" -w "%{http_code}" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" \
  "$BASE/api/auth/register")"
[[ "$REG2_CODE" == "409" ]] && ok "register conflict ok" || { cat "$REG2_JSON"; fail "attendu 409, reçu $REG2_CODE"; }
echo

# --- 4) LOGIN WRONG PASS -> 401
echo "4) LOGIN WRONG PASS -> 401 + JSON"
BAD_CODE="$(curl -sS -o "$BAD_JSON" -w "%{http_code}" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"WRONG\"}" \
  "$BASE/api/auth/login")"
[[ "$BAD_CODE" == "401" ]] && ok "login wrong pass ok" || { cat "$BAD_JSON"; fail "attendu 401, reçu $BAD_CODE"; }
echo

# --- 5) LIST FILES sans token -> 401
echo "5) LIST FILES sans token -> 401 JSON"
LIST_NOAUTH_CODE="$(curl -sS -o "$LIST_NOAUTH_JSON" -w "%{http_code}" \
  "$BASE/api/files")"
[[ "$LIST_NOAUTH_CODE" == "401" ]] && ok "list sans token ok" || { cat "$LIST_NOAUTH_JSON"; fail "attendu 401, reçu $LIST_NOAUTH_CODE"; }
echo

# --- 6) LIST FILES (token) -> 200
echo "6) LIST FILES (token) -> 200"
LIST_JSON="$(curl -sS "${HDR_AUTH[@]}" "$BASE/api/files")"
echo "$LIST_JSON" | jq -e '.' >/dev/null || fail "list json invalide"
ok "list ok"
echo

# --- 7) UPLOAD / DOWNLOAD / DELETE
echo "7) UPLOAD / DOWNLOAD / DELETE"
echo "hello grand!" > /tmp/jsc_gt.txt

UP_CODE="$(curl -sS -o "$UP_JSON" -w "%{http_code}" \
  "${HDR_AUTH[@]}" \
  -F "file=@/tmp/jsc_gt.txt;filename=jsc_gt.txt" \
  "$BASE/api/files/upload")"
[[ "$UP_CODE" == "200" ]] && ok "upload ok" || { cat "$UP_JSON"; fail "upload code=$UP_CODE"; }

LIST2_JSON="$(curl -sS "${HDR_AUTH[@]}" "$BASE/api/files")"
ID="$(echo "$LIST2_JSON" | jq -r '.[0].id')"
[[ "$ID" != "null" && -n "$ID" ]] || { echo "$LIST2_JSON"; fail "id manquant après upload"; }
echo "file id = $ID"

DL_PATH="/tmp/jsc_download_${ID}.bin"
DL_CODE="$(curl -sS -o "$DL_PATH" -w "%{http_code}" \
  "${HDR_AUTH[@]}" \
  "$BASE/api/files/$ID/download")"
[[ "$DL_CODE" == "200" ]] || fail "download attendu 200, reçu $DL_CODE"
DL_SIZE="$(wc -c < "$DL_PATH" | tr -d ' ')"
[[ "$DL_SIZE" -gt 0 ]] && ok "download ok (non vide)" || fail "download vide"

DEL_CODE="$(curl -sS -o "$DEL_JSON" -w "%{http_code}" \
  "${HDR_AUTH[@]}" \
  -X DELETE "$BASE/api/files/$ID")"
[[ "$DEL_CODE" == "200" ]] && ok "delete ok" || { cat "$DEL_JSON"; fail "delete code=$DEL_CODE"; }
echo

# --- 8) CROSS-USER ACCESS -> 404/404
echo "8) CROSS-USER ACCESS (hide existence) -> 404/404"
TS2="$((TS+1))"
EMAIL2="grandtest2_${TS2}@local.dev"
PASS2="Passw0rd!${TS2}"

curl -sS -o /dev/null -w "%{http_code}" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL2\",\"password\":\"$PASS2\"}" \
  "$BASE/api/auth/register" >/dev/null

LOGIN2_JSON="$(curl -sS \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL2\",\"password\":\"$PASS2\"}" \
  "$BASE/api/auth/login")"
TOKEN2="$(echo "$LOGIN2_JSON" | jq -r '.token')"
[[ "$TOKEN2" != "null" && -n "$TOKEN2" ]] || { echo "$LOGIN2_JSON"; fail "token2 manquant"; }
HDR_AUTH2=(-H "Authorization: Bearer $TOKEN2")

echo "u2" > /tmp/jsc_u2.txt
curl -sS -o /dev/null -w "%{http_code}" \
  "${HDR_AUTH2[@]}" \
  -F "file=@/tmp/jsc_u2.txt;filename=jsc_u2.txt" \
  "$BASE/api/files/upload" >/dev/null

LISTU2="$(curl -sS "${HDR_AUTH2[@]}" "$BASE/api/files")"
IDU2="$(echo "$LISTU2" | jq -r '.[0].id')"
[[ -n "$IDU2" && "$IDU2" != "null" ]] || { echo "$LISTU2"; fail "id user2 manquant"; }

XDL="$(curl -sS -o /dev/null -w "%{http_code}" "${HDR_AUTH[@]}" "$BASE/api/files/$IDU2/download")"
XDEL="$(curl -sS -o /dev/null -w "%{http_code}" "${HDR_AUTH[@]}" -X DELETE "$BASE/api/files/$IDU2")"
[[ "$XDL" == "404" && "$XDEL" == "404" ]] && ok "cross-user hidden ok (404/404)" || fail "cross-user attendu 404/404, reçu $XDL/$XDEL"
echo

# --- B5) UPLOAD TOO LARGE -> 413
# IMPORTANT: use a different "IP" (X-Forwarded-For) to avoid rate limit interfering.
echo "B5) UPLOAD TOO LARGE -> 413"
BIG="/tmp/jsc_big.bin"
dd if=/dev/zero of="$BIG" bs=1M count="$B5_MIB" status=none
ls -lh "$BIG"
wc -c "$BIG"

HDR_BIGIP=(-H "X-Forwarded-For: 198.51.100.99")

B5_CODE="$(curl -sS -o "$B5_JSON" -w "%{http_code}" \
  "${HDR_AUTH[@]}" "${HDR_BIGIP[@]}" \
  -F "file=@$BIG;filename=big.bin" \
  "$BASE/api/files/upload")"

[[ "$B5_CODE" == "413" ]] && ok "upload too large ok (413)" || {
  echo "HTTP $B5_CODE"
  cat "$B5_JSON" || true
  fail "attendu 413, reçu $B5_CODE"
}
echo

# --- 9) RATE LIMIT LOGIN -> 429
echo "9) RATE LIMIT LOGIN (IP) -> 429"
hit429="no"
for i in $(seq 1 30); do
  CODE="$(curl -sS -o /dev/null -w "%{http_code}" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$EMAIL\",\"password\":\"WRONG\"}" \
    "$BASE/api/auth/login")"
  if [[ "$CODE" == "429" ]]; then hit429="yes"; break; fi
done
[[ "$hit429" == "yes" ]] && ok "rate limit login ok (429)" || fail "rate limit login: 429 non atteint"
echo

# --- 10) RATE LIMIT UPLOAD -> 429
echo "10) RATE LIMIT UPLOAD (IP) -> 429"
echo "small" > /tmp/jsc_small.txt
hit429="no"
for i in $(seq 1 80); do
  CODE="$(curl -sS -o /dev/null -w "%{http_code}" \
    "${HDR_AUTH[@]}" \
    -F "file=@/tmp/jsc_small.txt;filename=small_${i}.txt" \
    "$BASE/api/files/upload")"
  if [[ "$CODE" == "429" ]]; then hit429="yes"; break; fi
done
[[ "$hit429" == "yes" ]] && ok "rate limit upload ok (429)" || fail "rate limit upload: 429 non atteint"

echo
echo "=============================="
echo "✅ GRAND TEST OK"
