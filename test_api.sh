#!/usr/bin/env bash
set -euo pipefail

API="${API:-http://127.0.0.1:8081}"

EMAIL="${EMAIL:-test@example.com}"
PASSWORD="${PASSWORD:-Test1234!}"

TEST_FILE="${TEST_FILE:-./test_upload.txt}"
echo "hello upload $(date)" > "$TEST_FILE"

echo "== API: $API =="
echo

echo "== 1) Health =="
curl -sS -i "$API/health" || true
echo -e "\n"

echo "== 2) Register (peut retourner 409 si déjà créé) =="
curl -sS -i -X POST "$API/auth/register" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" || true
echo -e "\n"

echo "== 3) Login =="
LOGIN_JSON=$(curl -sS -X POST "$API/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}")

echo "$LOGIN_JSON"
echo

TOKEN=$(echo "$LOGIN_JSON" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')

if [[ -z "${TOKEN:-}" ]]; then
  echo "❌ Token introuvable dans la réponse login."
  echo "Réponse brute: $LOGIN_JSON"
  exit 1
fi

echo "✅ Token OK (début): ${TOKEN:0:20}..."
echo

echo "== 4) Upload =="
UPLOAD_JSON=$(curl -sS -X POST "$API/files/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@$TEST_FILE")

echo "$UPLOAD_JSON"
echo

# Essaie de récupérer un id (adapte si ton champ s'appelle autrement)
FILE_ID=$(echo "$UPLOAD_JSON" | sed -n 's/.*"id":"\([^"]*\)".*/\1/p')
if [[ -z "${FILE_ID:-}" ]]; then
  FILE_ID=$(echo "$UPLOAD_JSON" | sed -n 's/.*"file_id":"\([^"]*\)".*/\1/p')
fi

if [[ -z "${FILE_ID:-}" ]]; then
  echo "⚠️ Impossible d'extraire l'ID fichier. Regarde la réponse upload ci-dessus."
else
  echo "✅ File ID: $FILE_ID"
fi
echo

echo "== 5) List files =="
curl -sS -i "$API/files" -H "Authorization: Bearer $TOKEN" || true
echo -e "\n"

if [[ -n "${FILE_ID:-}" ]]; then
  echo "== 6) Download =="
  curl -sS -L -o downloaded.txt \
    -H "Authorization: Bearer $TOKEN" \
    "$API/files/$FILE_ID/download" || true
  echo "✅ Downloaded -> downloaded.txt"
  echo

  echo "== 7) Delete =="
  curl -sS -i -X DELETE "$API/files/$FILE_ID" \
    -H "Authorization: Bearer $TOKEN" || true
  echo -e "\n"
fi

echo "✅ Tests terminés."
