use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header as JwtHeader, Validation};
use once_cell::sync::Lazy;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sqlx::Row;
use std::time::Duration;
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
    exp: usize,  // expiration (unix timestamp)
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

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let h = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let h = h.trim();
    let token = h
        .strip_prefix("Bearer ")
        .or_else(|| h.strip_prefix("bearer "))?;
    Some(token.trim().to_string())
}

/// Utilisé par files.rs (fallback) si tu extrais via headers
pub fn get_user_from_headers(headers: &HeaderMap) -> Result<String, String> {
    let token = bearer_token(headers).ok_or_else(|| "Header Authorization manquant".to_string())?;
    verify_jwt_email(&token)
}

// ================================
// AuthUser + Middleware
// ================================
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub email: String,
}

/// Middleware: protège /files/* (route_layer dans api/mod.rs)
pub async fn auth_middleware(mut req: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    let token = bearer_token(req.headers()).ok_or(StatusCode::UNAUTHORIZED)?;
    let email = verify_jwt_email(&token).map_err(|_| StatusCode::UNAUTHORIZED)?;
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
    pub token: Option<String>,
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

static LOGIN_ATTEMPTS: Lazy<std::sync::Mutex<std::collections::HashMap<String, AttemptInfo>>> =
    Lazy::new(|| std::sync::Mutex::new(std::collections::HashMap::new()));

const MAX_FAILED_ATTEMPTS: u32 = 5;
const BLOCK_DURATION: std::time::Duration = std::time::Duration::from_secs(5 * 60);

// ================================
// HANDLER : /register
// ================================
pub async fn register_handler(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let exists: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM users WHERE email = ?1 LIMIT 1")
        .bind(&payload.email)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| db_err("check user", e))?;

    if exists.is_some() {
        warn!(email = %payload.email, "register_conflict_email_exists");
        return Err(ApiError::conflict(
            "Un utilisateur avec cet email existe déjà",
        ));
    }

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|e| ApiError::internal_msg(format!("Erreur hash: {e}")))?
        .to_string();

    sqlx::query("INSERT INTO users (email, password_hash) VALUES (?1, ?2)")
        .bind(&payload.email)
        .bind(&hashed_password)
        .execute(&state.db)
        .await
        .map_err(|e| db_err("insert user", e))?;

    info!(email = %payload.email, "register_ok");

    Ok(Json(AuthResponse {
        status: "ok".to_string(),
        message: "Utilisateur créé".to_string(),
        email: Some(payload.email),
        token: None,
    }))
}

// ================================
// HANDLER : /login
// ================================
pub async fn login_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<LoginPayload>,
) -> ApiResult<Json<AuthResponse>> {
    // ✅ rate limit IP (A3) -> ApiError direct
    rate_limit_or_err(&headers, "login", 10, Duration::from_secs(60))?;

    // anti bruteforce mémoire (par email)
    {
        let mut map = LOGIN_ATTEMPTS.lock().unwrap();
        let entry = map.entry(payload.email.clone()).or_insert(AttemptInfo {
            failed: 0,
            blocked_until: None,
        });

        if let Some(until) = entry.blocked_until {
            if std::time::SystemTime::now() < until {
                warn!(email = %payload.email, "login_blocked_memory_rate_limit");
                return Err(ApiError::rate_limited(
                    "Trop de tentatives, réessaie dans quelques minutes.",
                ));
            } else {
                entry.blocked_until = None;
                entry.failed = 0;
            }
        }
    }

    let row = sqlx::query(r#"SELECT email, password_hash FROM users WHERE email = ?1"#)
        .bind(&payload.email)
        .fetch_one(&state.db)
        .await
        .map_err(|_| ApiError::unauthorized_msg("Email ou mot de passe invalide"))?;

    let email: String = row.try_get("email").unwrap_or_default();
    let stored_hash: String = row.try_get("password_hash").unwrap_or_default();

    let valid = verify_password(&stored_hash, &payload.password);

    {
        let mut map = LOGIN_ATTEMPTS.lock().unwrap();
        let entry = map.entry(payload.email.clone()).or_insert(AttemptInfo {
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
        warn!(email = %payload.email, "login_failed_invalid_credentials");
        return Err(ApiError::unauthorized_msg("Email ou mot de passe invalide"));
    }

    let token = create_jwt(&email)?;

    info!(email = %payload.email, "login_ok");

    Ok(Json(AuthResponse {
        status: "ok".to_string(),
        message: "Connexion réussie".to_string(),
        email: Some(payload.email),
        token: Some(token),
    }))
}

fn verify_password(hashed: &str, password: &str) -> bool {
    let parsed = match PasswordHash::new(hashed) {
        Ok(h) => h,
        Err(_) => return false,
    };

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn bearer_token_extracts() {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, "Bearer ABC".parse().unwrap());
        assert_eq!(bearer_token(&h).as_deref(), Some("ABC"));
    }

    #[test]
    fn jwt_roundtrip_works() {
        // Crée un token puis vérifie qu'on récupère bien l'email
        let token = create_jwt("a@b.com").expect("jwt");
        let email = verify_jwt_email(&token).expect("verify");
        assert_eq!(email, "a@b.com");
    }

    #[test]
    fn get_user_from_headers_requires_bearer() {
        let mut h = HeaderMap::new();
        h.insert(AUTHORIZATION, "Token nope".parse().unwrap());
        assert!(get_user_from_headers(&h).is_err());
    }
}
