#!/usr/bin/env bash
set -euo pipefail

BASE="http://127.0.0.1:8081/api"

EMAIL="test$(date +%s)@local.dev"
PASS="Passw0rd!123"

echo "== 1) HEALTH =="
curl -s -i "$BASE/health" | sed -n '1,12p'
echo

echo "== 2) REGISTER =="
REG_BODY=$(printf '{"email":"%s","password":"%s"}' "$EMAIL" "$PASS")
curl -s -i -H "Content-Type: application/json" -d "$REG_BODY" "$BASE/auth/register" | sed -n '1,40p'
echo

echo "== 3) LOGIN (récupère token) =="
LOGIN_BODY=$(printf '{"email":"%s","password":"%s"}' "$EMAIL" "$PASS")
LOGIN_JSON=$(curl -s -H "Content-Type: application/json" -d "$LOGIN_BODY" "$BASE/auth/login")
echo "$LOGIN_JSON"
echo

TOKEN=$(echo "$LOGIN_JSON" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

if [[ -z "${TOKEN:-}" ]]; then
  echo "❌ Token introuvable dans la réponse login."
  exit 1
fi

AUTH="Authorization: Bearer $TOKEN"

echo "== 4) LIST FILES (doit être 200 et []) =="
curl -s -i -H "$AUTH" "$BASE/files" | sed -n '1,60p'
echo

echo "== 5) UPLOAD fichier clean (txt) =="
TMP_OK="/tmp/jsc_ok.txt"
echo "hello jsecure" > "$TMP_OK"

UPLOAD_RESP=$(curl -s -i -H "$AUTH" -F "file=@${TMP_OK}" "$BASE/files/upload")
echo "$UPLOAD_RESP" | sed -n '1,80p'
echo

echo "== 6) LIST FILES (doit contenir le fichier) =="
LIST_JSON=$(curl -s -H "$AUTH" "$BASE/files")
echo "$LIST_JSON"
echo

FILE_ID=$(echo "$LIST_JSON" | sed -n 's/.*"id":\([0-9]\+\).*/\1/p' | head -n 1)

if [[ -z "${FILE_ID:-}" ]]; then
  echo "❌ Impossible d'extraire un id de fichier depuis /files."
  exit 1
fi

echo "== 7) DOWNLOAD (doit télécharger) =="
curl -s -i -H "$AUTH" "$BASE/files/${FILE_ID}/download" -o "/tmp/jsc_download_${FILE_ID}.bin"
ls -lah "/tmp/jsc_download_${FILE_ID}.bin"
echo

echo "== 8) DELETE =="
curl -s -i -H "$AUTH" -X DELETE "$BASE/files/${FILE_ID}" | sed -n '1,80p'
echo

echo "== 9) LIST FILES (doit redevenir []) =="
curl -s -i -H "$AUTH" "$BASE/files" | sed -n '1,80p'
echo

echo "== 10) UPLOAD interdit (exe) -> doit refuser =="
TMP_EXE="/tmp/jsc_bad.exe"
echo "MZFAKE" > "$TMP_EXE"
curl -s -i -H "$AUTH" -F "file=@${TMP_EXE}" "$BASE/files/upload" | sed -n '1,120p'
echo

echo "✅ Fin des tests serveur."
