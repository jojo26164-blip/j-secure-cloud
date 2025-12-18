#!/usr/bin/env bash
set -euo pipefail

API="${API:-http://127.0.0.1:8081}"
EMAIL="${EMAIL:-test@example.com}"
PASSWORD="${PASSWORD:-Test1234!}"
BAD_PASSWORD="${BAD_PASSWORD:-WrongPass!}"

TMPDIR="$(mktemp -d)"
cleanup(){ rm -rf "$TMPDIR"; }
trap cleanup EXIT

PASS(){ echo "✅ $1"; }
FAIL(){ echo "❌ $1"; exit 1; }

http_code() {
  curl -sS -o /dev/null -w "%{http_code}" "$@"
}

echo "=============================="
echo "J-Secure Cloud — API FULL TEST"
echo "API = $API"
echo "EMAIL = $EMAIL"
echo "=============================="
echo

# 1) Health
echo "== 1) Health =="
HEALTH_CODE=$(http_code "$API/health" || true)
HEALTH_BODY=$(curl -sS "$API/health" || true)
echo "HTTP $HEALTH_CODE"
echo "$HEALTH_BODY"
[[ "$HEALTH_CODE" == "200" ]] || FAIL "Health doit être 200"

python3 -c 'import sys,json; d=json.loads(sys.stdin.read()); assert d.get("status")=="ok";' <<<"$HEALTH_BODY" \
  || FAIL "Health JSON inattendu (status != ok)"
PASS "Health OK"
echo

# 2) Register (409 accepté)
echo "== 2) Register (200/201 ou 409 accepté) =="
REG_CODE=$(http_code -X POST "$API/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" || true)
echo "HTTP $REG_CODE"
if [[ "$REG_CODE" != "200" && "$REG_CODE" != "201" && "$REG_CODE" != "409" ]]; then
  FAIL "Register doit être 200/201/409, pas $REG_CODE"
fi
PASS "Register OK (ou déjà existant)"
echo

# 3) Login OK + token
echo "== 3) Login (OK) =="
LOGIN_JSON=$(curl -sS -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")
echo "$LOGIN_JSON"

TOKEN=$(python3 -c 'import sys,json; print(json.loads(sys.stdin.read() or "{}").get("token",""))' <<<"$LOGIN_JSON")
[[ -n "${TOKEN:-}" ]] || FAIL "Token introuvable dans la réponse login"
PASS "Login OK + token"
echo "Token (début): ${TOKEN:0:25}..."
echo

# 4) Login mauvais mot de passe -> 401/403 attendu
echo "== 4) Login (mauvais mot de passe) => 401/403 attendu =="
BAD_CODE=$(http_code -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$BAD_PASSWORD\"}" || true)
echo "HTTP $BAD_CODE"
[[ "$BAD_CODE" == "401" || "$BAD_CODE" == "403" ]] || FAIL "Mauvais password doit être 401/403"
PASS "Login mauvais password => $BAD_CODE"
echo

# 5) Accès /files sans token -> 401/403 attendu
echo "== 5) /files sans token => 401/403 attendu =="
NOAUTH_CODE=$(http_code "$API/files" || true)
echo "HTTP $NOAUTH_CODE"
[[ "$NOAUTH_CODE" == "401" || "$NOAUTH_CODE" == "403" ]] || FAIL "/files sans token doit être 401/403"
PASS "/files sans token => $NOAUTH_CODE"
echo

# 6) Upload
echo "== 6) Upload =="
UPLOAD_FN="test_upload_$(date +%s).txt"
UPLOAD_PATH="$TMPDIR/$UPLOAD_FN"
echo "hello upload $(date)" > "$UPLOAD_PATH"

UPLOAD_JSON=$(curl -sS -X POST "$API/files/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@$UPLOAD_PATH")
echo "$UPLOAD_JSON"
PASS "Upload OK (réponse reçue)"
echo

# 7) List files
echo "== 7) List files =="
LIST_CODE=$(http_code -H "Authorization: Bearer $TOKEN" "$API/files" || true)
echo "HTTP $LIST_CODE"
[[ "$LIST_CODE" == "200" ]] || FAIL "List files doit être 200 (got $LIST_CODE)"

LIST_JSON=$(curl -sS -H "Authorization: Bearer $TOKEN" "$API/files")
echo "$LIST_JSON"
PASS "List files OK"
echo

# 8) Extraire l'ID du fichier uploadé via la liste
echo "== 8) Extract file id (via list) =="
FILE_ID=$(python3 -c '
import sys,json
fn=sys.argv[1]
arr=json.loads(sys.stdin.read() or "[]")
ids=[x.get("id") for x in arr if x.get("filename")==fn and isinstance(x.get("id"), int)]
print(max(ids) if ids else "")
' "$UPLOAD_FN" <<<"$LIST_JSON")

[[ -n "${FILE_ID:-}" ]] || FAIL "Impossible de trouver l'ID du fichier '$UPLOAD_FN' dans la liste"
PASS "File ID trouvé = $FILE_ID"
echo

# 9) Download + vérification contenu
echo "== 9) Download & verify =="
DL_PATH="$TMPDIR/downloaded.txt"
DL_CODE=$(http_code -L -o "$DL_PATH" \
  -H "Authorization: Bearer $TOKEN" \
  "$API/files/$FILE_ID/download" || true)
echo "HTTP $DL_CODE"
[[ "$DL_CODE" == "200" ]] || FAIL "Download doit être 200 (got $DL_CODE)"

diff -q "$UPLOAD_PATH" "$DL_PATH" >/dev/null 2>&1 || FAIL "Contenu download différent de l'upload"
PASS "Download OK + contenu identique"
echo

# 10) Delete
echo "== 10) Delete =="
DEL_CODE=$(http_code -X DELETE "$API/files/$FILE_ID" \
  -H "Authorization: Bearer $TOKEN" || true)
echo "HTTP $DEL_CODE"
[[ "$DEL_CODE" == "200" || "$DEL_CODE" == "204" ]] || FAIL "Delete doit être 200/204 (got $DEL_CODE)"
PASS "Delete OK"
echo

# 11) Vérifie que le fichier n'est plus listé
echo "== 11) Verify removed from list =="
LIST2_JSON=$(curl -sS -H "Authorization: Bearer $TOKEN" "$API/files")
FOUND_AGAIN=$(python3 -c '
import sys,json
fid=int(sys.argv[1])
arr=json.loads(sys.stdin.read() or "[]")
print(any(x.get("id")==fid for x in arr))
' "$FILE_ID" <<<"$LIST2_JSON")

[[ "$FOUND_AGAIN" == "False" ]] || FAIL "Le fichier $FILE_ID est encore présent dans la liste"
PASS "Fichier supprimé n'apparaît plus dans la liste"
echo

echo "=============================="
echo "✅ FULL TESTS OK"
echo "=============================="
