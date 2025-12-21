# J-Secure Cloud — Progress

## Freeze stable: v0.1.0-b4
Date: 2025-12-21

### OK
- /api/health: 200 JSON (db ok), 503 si DB down
- Auth: register/login JWT OK (argon2)
- Files:
  - list: 200 [] (token)
  - upload: 200 + scan ClamAV + basic scan + extensions forbidden
  - download: 200 non vide (owner only, hide existence => 404)
  - delete: 200 (owner only, hide existence => 404)
- Rate limit IP:
  - login: 429 après ~10/min
  - upload: 429 après ~30/min
- Errors: format JSON unifié via ApiError
- Tests: cargo test OK + grand test script OK
- Clippy: OK (-D warnings)

### Policy sécurité
- Cross-user access: 404/404 (hide existence)
- Upload forbidden ext: FILE_REFUSED (400)
