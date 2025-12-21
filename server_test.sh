#!/usr/bin/env bash
set -euo pipefail

BASE="http://127.0.0.1:8081/api"

echo "== 1) HEALTH =="
curl -i "$BASE/health"
echo

EMAIL="test$(date +%s)@local.dev"
PASS="Passw0rd!"

echo "== 2) REGISTER =="
curl -s -i -X POST "$BASE/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}"
echo

echo "== 3) LOGIN (récupère token) =="
TOKEN=$(curl -s -X POST "$BASE/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASS\"}" \
  | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
test -n "$TOKEN" || { echo "❌ token vide"; exit 1; }
echo "TOKEN OK"
echo

echo "== 4) LIST FILES (doit être 200 et []) =="
code=$(curl -s -o /tmp/jsc_list.json -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE/files")
echo "HTTP $code"
test "$code" = "200" || { echo "❌ attendu 200"; cat /tmp/jsc_list.json; exit 1; }
cat /tmp/jsc_list.json
echo

echo "== 5) UPLOAD fichier clean (txt) =="
echo "hello from jsc" > /tmp/jsc_ok.txt
code=$(curl -s -o /tmp/jsc_up.json -w "%{http_code}" \
  -X POST "$BASE/files/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/jsc_ok.txt;filename=jsc_ok.txt")
echo "HTTP $code"
test "$code" = "200" || { echo "❌ attendu 200"; cat /tmp/jsc_up.json; exit 1; }
cat /tmp/jsc_up.json
echo

echo "== 6) LIST FILES (doit contenir le fichier) =="
FILES=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/files")
echo "$FILES"
ID=$(echo "$FILES" | sed -n 's/.*"id":\([0-9]\+\).*/\1/p' | head -n1)
test -n "$ID" || { echo "❌ Impossible d'extraire un id"; exit 1; }
echo "file id = $ID"
echo

echo "== 7) DOWNLOAD (doit être 200 et non vide) =="
OUT="/tmp/jsc_download_${ID}.bin"
code=$(curl -s -o "$OUT" -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE/files/$ID/download")
echo "HTTP $code"
test "$code" = "200" || { echo "❌ attendu 200"; ls -l "$OUT" || true; exit 1; }
test -s "$OUT" || { echo "❌ fichier download vide"; ls -l "$OUT"; exit 1; }
ls -l "$OUT"
echo

echo "== 8) DELETE =="
code=$(curl -s -o /tmp/jsc_del.json -w "%{http_code}" \
  -X DELETE \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE/files/$ID")
echo "HTTP $code"
test "$code" = "200" || { echo "❌ attendu 200"; cat /tmp/jsc_del.json; exit 1; }
cat /tmp/jsc_del.json
echo

echo "== 9) LIST FILES (doit redevenir []) =="
code=$(curl -s -o /tmp/jsc_list2.json -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  "$BASE/files")
echo "HTTP $code"
test "$code" = "200" || { echo "❌ attendu 200"; cat /tmp/jsc_list2.json; exit 1; }
cat /tmp/jsc_list2.json
echo

echo "== 10) UPLOAD interdit (exe) -> doit refuser 400 =="
echo "MZ" > /tmp/jsc_bad.exe
code=$(curl -s -o /tmp/jsc_bad.json -w "%{http_code}" \
  -X POST "$BASE/files/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/jsc_bad.exe;filename=jsc_bad.exe")
echo "HTTP $code"
test "$code" = "400" || { echo "❌ attendu 400"; cat /tmp/jsc_bad.json; exit 1; }
cat /tmp/jsc_bad.json
echo

echo "== 11) INVALID TOKEN -> 401 =="
code=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer INVALIDTOKEN" \
  "$BASE/files")
echo "HTTP $code"
test "$code" = "401" || { echo "❌ attendu 401"; exit 1; }
echo

echo "== 12) CROSS-USER ACCESS -> 403 ou 404 (hide existence) =="

EMAIL_A="a$(date +%s)@local.dev"
PASS_A="Passw0rd!A"
curl -s -X POST "$BASE/auth/register" -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL_A\",\"password\":\"$PASS_A\"}" >/dev/null
TOKEN_A=$(curl -s -X POST "$BASE/auth/login" -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL_A\",\"password\":\"$PASS_A\"}" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

EMAIL_B="b$(date +%s)@local.dev"
PASS_B="Passw0rd!B"
curl -s -X POST "$BASE/auth/register" -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL_B\",\"password\":\"$PASS_B\"}" >/dev/null
TOKEN_B=$(curl -s -X POST "$BASE/auth/login" -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL_B\",\"password\":\"$PASS_B\"}" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

echo "hello" > /tmp/jsc_owner_test.txt
curl -s -X POST "$BASE/files/upload" \
  -H "Authorization: Bearer $TOKEN_A" \
  -F "file=@/tmp/jsc_owner_test.txt;filename=jsc_owner_test.txt" >/dev/null

ID_A=$(curl -s "$BASE/files" -H "Authorization: Bearer $TOKEN_A" \
  | sed -n 's/.*"id":\([0-9]\+\).*/\1/p' | head -n1)
echo "file id A = $ID_A"
test -n "$ID_A" || { echo "❌ impossible de récupérer l'id"; exit 1; }

code=$(curl -s -o /dev/null -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN_B" \
  "$BASE/files/$ID_A/download")
echo "download cross-user HTTP $code"
test "$code" = "403" -o "$code" = "404" || { echo "❌ attendu 403 ou 404"; exit 1; }

code=$(curl -s -o /dev/null -w "%{http_code}" \
  -X DELETE \
  -H "Authorization: Bearer $TOKEN_B" \
  "$BASE/files/$ID_A")
echo "delete cross-user HTTP $code"
test "$code" = "404" || { echo "❌ attendu 404"; exit 1; }

curl -s -X DELETE -H "Authorization: Bearer $TOKEN_A" "$BASE/files/$ID_A" >/dev/null
echo

echo "== 13) RATE LIMIT LOGIN (IP) -> doit bloquer après ~10/min =="
EMAIL_RL="rl$(date +%s)@local.dev"
PASS_RL="Passw0rd!RL"
curl -s -X POST "$BASE/auth/register" -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL_RL\",\"password\":\"$PASS_RL\"}" >/dev/null

blocked=0
for i in $(seq 1 12); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"email\":\"$EMAIL_RL\",\"password\":\"WRONGPASS\"}")
  echo "try $i => HTTP $code"
  if [ "$code" = "429" ]; then
    blocked=1
    break
  fi
done
test "$blocked" = "1" || { echo "❌ rate limit login non déclenché"; exit 1; }
echo

echo "== 14) RATE LIMIT UPLOAD (IP) -> doit renvoyer 429 (pas 400) =="
echo "x" > /tmp/jsc_rl_upload.txt
blocked=0
for i in $(seq 1 50); do
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$BASE/files/upload" \
    -H "Authorization: Bearer $TOKEN_A" \
    -F "file=@/tmp/jsc_rl_upload.txt;filename=jsc_rl_upload_$i.txt")
  echo "upload $i => HTTP $code"
  if [ "$code" = "429" ]; then
    blocked=1
    break
  fi
done
test "$blocked" = "1" || { echo "❌ rate limit upload non déclenché (ou pas en 429)"; exit 1; }

echo "✅ B1 OK: invalid token / cross-user / rate-limit login+upload"
