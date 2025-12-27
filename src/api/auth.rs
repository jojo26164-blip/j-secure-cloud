use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{
        header::{AUTHORIZATION, COOKIE, SET_COOKIE},
        HeaderMap, StatusCode,
    },
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header as JwtHeader, Validation};
use once_cell::sync::Lazy;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::{collections::HashMap, sync::Mutex, time::Duration};
use tracing::{info, warn};

use crate::api::error::{db_err, ApiError, ApiResult};
use crate::api::rate_limit::rate_limit_or_err;
use crate::api::AppState;

// =====================
// JWT CONFIG
// =====================
fn jwt_secret_bytes() -> Vec<u8> {
    std::env::var("JWT_SECRET")
        .unwrap_or_else(|_| "DEV_SECRET_A_CHANGER".to_string())
        .into_bytes()
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String, // email
    exp: usize,  // unix ts
}

fn create_jwt(email: &str) -> ApiResult<String> {
    let exp = (Utc::now() + ChronoDuration::hours(24)).timestamp() as usize;
    let claims = Claims {
        sub: email.to_string(),
        exp,
    };
    encode(
        &JwtHeader::default(),
        &claims,
        &EncodingKey::from_secret(&jwt_secret_bytes()),
    )
    .map_err(|e| ApiError::internal_msg(format!("Erreur création JWT: {e}")))
}

fn verify_jwt_email(token: &str) -> Result<String, String> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(&jwt_secret_bytes()),
        &Validation::default(),
    )
    .map_err(|_| "Token invalide ou expiré".to_string())?;
    Ok(token_data.claims.sub)
}

// =====================
// Cookie helpers
// =====================
fn get_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            if k.trim() == name {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    // 1) Authorization: Bearer ...
    if let Some(h) = headers.get(AUTHORIZATION).and_then(|v| v.to_str().ok()) {
        let h = h.trim();
        if let Some(token) = h.strip_prefix("Bearer ").or_else(|| h.strip_prefix("bearer ")) {
            return Some(token.trim().to_string());
        }
    }
    // 2) Cookie: jwt=...
    get_cookie_value(headers, "jwt")
}

/// Utilisé par files/admin/me: extraction email depuis Authorization: Bearer OU cookie jwt
pub fn get_user_from_headers(headers: &HeaderMap) -> Result<String, String> {
    let token = bearer_token(headers).ok_or_else(|| "Auth manquante (Bearer ou cookie jwt)".to_string())?;
    verify_jwt_email(&token)
}

// ================================
// Middleware (si tu l'utilises)
// ================================
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub email: String,
}

/// Middleware exemple (si route_layer)
pub async fn auth_middleware(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let token = bearer_token(req.headers()).ok_or(StatusCode::UNAUTHORIZED)?;
    let email = verify_jwt_email(&token).map_err(|_| StatusCode::UNAUTHORIZED)?;

    // ✅ Check DB : user existe + pas bloqué
    let row = sqlx::query(
        r#"
        SELECT COALESCE(is_blocked, 0) AS is_blocked
        FROM users
        WHERE lower(email) = lower(?1)
        LIMIT 1
        "#,
    )
    .bind(&email)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let Some(row) = row else {
        // user supprimé => token invalide
        return Err(StatusCode::UNAUTHORIZED);
    };

    let is_blocked: i64 = row.try_get("is_blocked").unwrap_or(0);
    if is_blocked == 1 {
        return Err(StatusCode::FORBIDDEN);
    }

    req.extensions_mut().insert(AuthUser { email });
    Ok(next.run(req).await)
}

// ================================
// STRUCTS
// ================================
#[derive(Deserialize)]
pub struct LoginPayload {
    pub email: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub status: String,
    pub message: String,
    pub email: Option<String>,
    pub token: Option<String>, // on va mettre None (cookie only)
}

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
    pub password: String,
}

// ================================
// Anti-bruteforce mémoire (simple)
// ================================
#[derive(Debug, Clone)]
struct AttemptInfo {
    failed: u32,
    blocked_until: Option<std::time::SystemTime>,
}

static LOGIN_ATTEMPTS: Lazy<Mutex<HashMap<String, AttemptInfo>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

const MAX_FAILED_ATTEMPTS: u32 = 5;
const BLOCK_DURATION: Duration = Duration::from_secs(5 * 60);

// ================================
// HANDLER : /auth/register
// ================================
pub async fn register_handler(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let email = payload.email.trim().to_lowercase();
    let password = payload.password;

    if email.is_empty() {
        return Err(ApiError::bad_request("email vide"));
    }
    if password.len() < 8 {
        return Err(ApiError::bad_request("mot de passe trop court (min 8)"));
    }

    let exists: Option<(i64,)> =
        sqlx::query_as("SELECT 1 FROM users WHERE lower(email)=?1 LIMIT 1")
            .bind(&email)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| db_err("check user", e))?;

    if exists.is_some() {
        warn!(email = %email, "register_conflict_email_exists");
        return Err(ApiError::conflict("Un utilisateur avec cet email existe déjà"));
    }

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| ApiError::internal_msg(format!("Erreur hash: {e}")))?
        .to_string();

    sqlx::query("INSERT INTO users (email, password_hash) VALUES (?1, ?2)")
        .bind(&email)
        .bind(&hashed_password)
        .execute(&state.db)
        .await
        .map_err(|e| db_err("insert user", e))?;

    info!(email = %email, "register_ok");

    Ok(Json(AuthResponse {
        status: "ok".to_string(),
        message: "Utilisateur créé".to_string(),
        email: Some(email),
        token: None,
    }))
}

// ================================
// HANDLER : /auth/login  (COOKIE)
// ================================
pub async fn login_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<LoginPayload>,
) -> ApiResult<impl IntoResponse> {
    // Rate limit IP
    rate_limit_or_err(&headers, "login", 10, Duration::from_secs(60))?;

    let email_in = payload.email.trim().to_lowercase();
    let password_in = payload.password;

    if email_in.is_empty() || password_in.is_empty() {
        return Err(ApiError::bad_request("email + mot de passe requis"));
    }

    // Anti brute-force mémoire (par email)
    {
        let mut map = LOGIN_ATTEMPTS.lock().unwrap();
        let entry = map.entry(email_in.clone()).or_insert(AttemptInfo {
            failed: 0,
            blocked_until: None,
        });

        if let Some(until) = entry.blocked_until {
            if std::time::SystemTime::now() < until {
                warn!(email = %email_in, "login_blocked_memory_rate_limit");
                return Err(ApiError::rate_limited(
                    "Trop de tentatives, réessaie dans quelques minutes.",
                ));
            } else {
                entry.blocked_until = None;
                entry.failed = 0;
            }
        }
    }

    // Récupération user (hash + blocked)
    let row = sqlx::query(
        r#"
        SELECT email, password_hash, COALESCE(is_blocked, 0) AS is_blocked
        FROM users
        WHERE lower(email) = ?1
        LIMIT 1
        "#,
    )
    .bind(&email_in)
    .fetch_one(&state.db)
    .await
    .map_err(|_| ApiError::unauthorized_msg("Email ou mot de passe invalide"))?;

    let email_db: String = row.try_get("email").unwrap_or_default();
    let stored_hash: String = row.try_get("password_hash").unwrap_or_default();
    let is_blocked: i64 = row.try_get("is_blocked").unwrap_or(0);

    if is_blocked == 1 {
        warn!(email = %email_in, "login_blocked_user");
        return Err(ApiError::forbidden("compte bloqué"));
    }

    let valid = verify_password(&stored_hash, &password_in);

    // Update anti-bruteforce memory
    {
        let mut map = LOGIN_ATTEMPTS.lock().unwrap();
        let entry = map.entry(email_in.clone()).or_insert(AttemptInfo {
            failed: 0,
            blocked_until: None,
        });

        if valid {
            entry.failed = 0;
            entry.blocked_until = None;
        } else {
            entry.failed += 1;
            if entry.failed >= MAX_FAILED_ATTEMPTS {
                entry.blocked_until = Some(std::time::SystemTime::now() + BLOCK_DURATION);
            }
        }
    }

    if !valid {
        warn!(email = %email_in, "login_failed_invalid_credentials");
        return Err(ApiError::unauthorized_msg("Email ou mot de passe invalide"));
    }

    // JWT
    let token = create_jwt(&email_db)?;

    // Cookie sécurisé (prod: Secure; dev: sans Secure si http)
    // Mets COOKIE_SECURE=1 quand tu es en HTTPS
    let is_prod = std::env::var("COOKIE_SECURE").unwrap_or_default() == "1";
    let secure_flag = if is_prod { " Secure;" } else { "" };

    let cookie = format!(
        "jwt={}; HttpOnly; SameSite=Lax; Path=/; Max-Age={};{}",
        token,
        60 * 60 * 24,
        secure_flag
    );

    let mut resp = Json(AuthResponse {
        status: "ok".to_string(),
        message: "Connexion réussie".to_string(),
        email: Some(email_db),
        token: None, // IMPORTANT: on ne renvoie pas le JWT
    })
    .into_response();

    resp.headers_mut()
        .insert(SET_COOKIE, cookie.parse().unwrap());

    info!(email = %email_in, "login_ok");
    Ok(resp)
}

// ================================
// HANDLER : /auth/logout (COOKIE)
// ================================
pub async fn logout_handler() -> impl IntoResponse {
    // Expire le cookie
    let cookie = "jwt=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0";
    let mut resp = Json(serde_json::json!({"status":"ok","message":"logout"})).into_response();
    resp.headers_mut().insert(SET_COOKIE, cookie.parse().unwrap());
    resp
}

// ================================
// Password verify
// ================================
fn verify_password(hashed: &str, password: &str) -> bool {
    let parsed = match PasswordHash::new(hashed) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

// ======================
// Tests (optionnel)
// ======================
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn bearer_token_extracts_from_auth_header() {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, "Bearer ABC".parse().unwrap());
        assert_eq!(super::bearer_token(&h).as_deref(), Some("ABC"));
    }

    #[test]
    fn bearer_token_extracts_from_cookie() {
        let mut h = HeaderMap::new();
        h.insert(COOKIE, "a=1; jwt=XYZ; b=2".parse().unwrap());
        assert_eq!(super::bearer_token(&h).as_deref(), Some("XYZ"));
    }

    #[test]
    fn jwt_roundtrip_works() {
        let token = create_jwt("a@b.com").expect("jwt");
        let email = verify_jwt_email(&token).expect("verify");
        assert_eq!(email, "a@b.com");
    }
}
