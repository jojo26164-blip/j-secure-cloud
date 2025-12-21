#!/usr/bin/env bash
set -euo pipefail

BASE="${BASE:-http://127.0.0.1:8081}"

echo "=============================="
echo "J-Secure Cloud — GRAND TEST"
echo "BASE=$BASE"
echo "=============================="

need() { command -v "$1" >/dev/null 2>&1 || { echo "❌ missing: $1"; exit 1; }; }
need curl
need jq

pass(){ echo "✅ $1"; }
fail(){ echo "❌ $1"; exit 1; }

# -----------------------------
# 0) CORS PRE-FLIGHT
# -----------------------------
echo "== 0) CORS PRE-FLIGHT =="
code=$(curl -s -o /dev/null -w "%{http_code}" -X OPTIONS \
  -H "Origin: http://localhost:5173" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: authorization,content-type" \
  "$BASE/api/auth/login")
[[ "$code" == "200" || "$code" == "204" ]] && pass "CORS preflight (code=$code)" || fail "CORS preflight attendu 200/204, reçu $code"

# -----------------------------
# 1) HEALTH
# -----------------------------
echo "== 1) HEALTH =="
health_json=$(curl -s "$BASE/api/health")
echo "$health_json" | jq -e '.status' >/dev/null || fail "health JSON invalide"
pass "health ok"

# -----------------------------
# 2) REGISTER / LOGIN
# -----------------------------
echo "== 2) REGISTER / LOGIN =="
TS=$(date +%s)
EMAIL="grandtest_${TS}@local.dev"
PASS="Passw0rd!${TS}"

reg=$(curl -s -X POST "$BASE/api/auth/register" -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}")
echo "$reg" | jq -e '.status=="ok"' >/dev/null || fail "register KO: $reg"
pass "register ok"

login=$(curl -s -X POST "$BASE/api/auth/login" -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}")
TOKEN=$(echo "$login" | jq -r '.token // empty')
[[ -n "$TOKEN" ]] || fail "login sans token: $login"
pass "login ok (token obtenu)"

# -----------------------------
# 3) REGISTER CONFLICT -> 409
# -----------------------------
echo "== 3) REGISTER CONFLICT =="
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/auth/register" -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}")
[[ "$code" == "409" ]] && pass "register conflict ok" || fail "register conflict attendu 409, reçu $code"

# -----------------------------
# 4) LOGIN WRONG PASS -> 401
# -----------------------------
echo "== 4) LOGIN WRONG PASS =="
code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/auth/login" -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"WRONGPASS\"}")
[[ "$code" == "401" ]] && pass "login wrong pass ok" || fail "login wrong pass attendu 401, reçu $code"

# -----------------------------
# 5) LIST sans token -> 401 JSON
# -----------------------------
echo "== 5) LIST sans token =="
code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE/api/files")
[[ "$code" == "401" ]] && pass "list sans token ok" || fail "list sans token attendu 401, reçu $code"

# -----------------------------
# 6) LIST avec token -> 200 []
# -----------------------------
echo "== 6) LIST (token) =="
list=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/files")
echo "$list" | jq -e 'type=="array"' >/dev/null || fail "list pas array: $list"
pass "list ok"

# -----------------------------
# 7) UPLOAD ok -> LIST -> DOWNLOAD -> DELETE
# -----------------------------
echo "== 7) UPLOAD / DOWNLOAD / DELETE =="

TMPFILE="/tmp/jsc_gt.txt"
echo "hello-grand" > "$TMPFILE"

upload_code=$(curl -s -o /tmp/jsc_upload_resp.json -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@${TMPFILE};filename=jsc_gt.txt" \
  "$BASE/api/files/upload")
[[ "$upload_code" == "200" ]] || fail "upload attendu 200, reçu $upload_code: $(cat /tmp/jsc_upload_resp.json)"
pass "upload ok"

list2=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/files")
ID=$(echo "$list2" | jq -r '.[0].id // empty')
[[ -n "$ID" ]] || fail "ID introuvable dans list: $list2"
echo "file id = $ID"

# ✅ URL CORRIGÉE ICI:
DL="/tmp/jsc_download_${ID}.bin"
dl_code=$(curl -s -o "$DL" -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE/api/files/${ID}/download")
[[ "$dl_code" == "200" ]] || fail "download attendu 200, reçu $dl_code"
[[ -s "$DL" ]] || fail "download vide: $DL"
pass "download ok (non vide)"

del_code=$(curl -s -o /tmp/jsc_delete_resp.json -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  -X DELETE "$BASE/api/files/${ID}")
[[ "$del_code" == "200" ]] || fail "delete attendu 200, reçu $del_code: $(cat /tmp/jsc_delete_resp.json)"
pass "delete ok"

# -----------------------------
# 8) CROSS-USER ACCESS : must be 404 (hide existence)
# -----------------------------
echo "== 8) CROSS-USER ACCESS =="
TS2=$(date +%s)
EMAIL2="grandtest2_${TS2}@local.dev"
PASS2="Passw0rd!${TS2}"
curl -s -X POST "$BASE/api/auth/register" -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL2\",\"password\":\"$PASS2\"}" >/dev/null

login2=$(curl -s -X POST "$BASE/api/auth/login" -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL2\",\"password\":\"$PASS2\"}")
TOKEN2=$(echo "$login2" | jq -r '.token // empty')
[[ -n "$TOKEN2" ]] || fail "login2 sans token: $login2"

# user1 upload
echo "secret-user1" > /tmp/jsc_u1.txt
curl -s -H "Authorization: Bearer $TOKEN" -F "file=@/tmp/jsc_u1.txt;filename=u1.txt" "$BASE/api/files/upload" >/dev/null
u1_list=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/files")
ID1=$(echo "$u1_list" | jq -r '.[0].id // empty')
[[ -n "$ID1" ]] || fail "ID1 introuvable: $u1_list"

# user2 tries download/delete => 404 (hide)
code_d=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN2" "$BASE/api/files/${ID1}/download")
code_x=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN2" -X DELETE "$BASE/api/files/${ID1}")
[[ "$code_d" == "404" ]] || fail "cross-user download attendu 404, reçu $code_d"
[[ "$code_x" == "404" ]] || fail "cross-user delete attendu 404, reçu $code_x"
pass "cross-user hidden ok (404/404)"

# cleanup user1
curl -s -H "Authorization: Bearer $TOKEN" -X DELETE "$BASE/api/files/${ID1}" >/dev/null || true

# -----------------------------
# 9) RATE LIMIT LOGIN -> 429
# -----------------------------
echo "== 9) RATE LIMIT LOGIN =="
hit429=0
for i in $(seq 1 20); do
  c=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE/api/auth/login" -H "Content-Type: application/json" \
    -d "{\"email\":\"$EMAIL\",\"password\":\"WRONGPASS\"}")
  if [[ "$c" == "429" ]]; then hit429=1; break; fi
done
[[ "$hit429" == "1" ]] && pass "rate limit login ok (429)" || fail "rate limit login non déclenché"

# -----------------------------
# 10) RATE LIMIT UPLOAD -> 429
# -----------------------------
echo "== 10) RATE LIMIT UPLOAD =="
hit429=0
for i in $(seq 1 60); do
  echo "x$i" > /tmp/rl_up.txt
  c=$(curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $TOKEN" \
    -F "file=@/tmp/rl_up.txt;filename=rl_${i}.txt" "$BASE/api/files/upload")
  if [[ "$c" == "429" ]]; then hit429=1; break; fi
done
[[ "$hit429" == "1" ]] && pass "rate limit upload ok (429)" || fail "rate limit upload non déclenché"

echo "=============================="
echo "✅ GRAND TEST OK"
echo "=============================="
