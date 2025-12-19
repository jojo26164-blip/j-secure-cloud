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
use tracing::{info, warn};

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
    exp: usize,  // expiration
}

fn create_jwt(email: &str) -> Result<String, (StatusCode, String)> {
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
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Erreur création JWT: {e}"),
        )
    })
}

// ✅ Utilisé encore (fallback) si tu veux lire l'email depuis Authorization: Bearer <token>
pub fn get_user_from_headers(headers: &HeaderMap) -> Result<String, String> {
    let auth_header = headers
        .get(AUTHORIZATION)
        .ok_or_else(|| "Header Authorization manquant".to_string())?
        .to_str()
        .map_err(|_| "Header Authorization invalide".to_string())?;

    if !auth_header.starts_with("Bearer ") {
        return Err("Format Authorization invalide (attendu: Bearer <token>)".to_string());
    }

    let token = &auth_header[7..];
    verify_jwt_email(token)
}

// ================================
// AuthUser + Middleware (3.5)
// ================================
#[derive(Clone, Debug)]
pub struct AuthUser {
    pub email: String,
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let h = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let h = h.trim();
    let token = h
        .strip_prefix("Bearer ")
        .or_else(|| h.strip_prefix("bearer "))?;
    Some(token.trim().to_string())
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

// Middleware: protège /files/* (via route_layer dans api/mod.rs)
pub async fn auth_middleware(mut req: Request<Body>, next: Next) -> Result<Response, StatusCode> {
    let token = bearer_token(req.headers()).ok_or(StatusCode::UNAUTHORIZED)?;
    let email = verify_jwt_email(&token).map_err(|_| StatusCode::UNAUTHORIZED)?;

    // ✅ injecte l'utilisateur dans Extensions => Extension<AuthUser> dans files.rs
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
) -> Result<Json<AuthResponse>, (StatusCode, String)> {
    let exists: Option<(i64,)> = sqlx::query_as("SELECT 1 FROM users WHERE email = ?1 LIMIT 1")
        .bind(&payload.email)
        .fetch_optional(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Erreur DB (check user): {e}"),
            )
        })?;

    if exists.is_some() {
        warn!(email = %payload.email, "register_conflict_email_exists");
        return Err((
            StatusCode::CONFLICT,
            "Un utilisateur avec cet email existe déjà".to_string(),
        ));
    }

    let salt = SaltString::generate(&mut OsRng);
    let hashed_password = Argon2::default()
        .hash_password(payload.password.as_bytes(), &salt)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Erreur hash: {e}"),
            )
        })?
        .to_string();

    sqlx::query("INSERT INTO users (email, password_hash) VALUES (?1, ?2)")
        .bind(&payload.email)
        .bind(&hashed_password)
        .execute(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Erreur DB (insert user): {e}"),
            )
        })?;

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
    State(state): State<AppState>,
    Json(payload): Json<LoginPayload>,
) -> Result<Json<AuthResponse>, (StatusCode, String)> {
    // anti bruteforce
    {
        let mut map = LOGIN_ATTEMPTS.lock().unwrap();
        let entry = map.entry(payload.email.clone()).or_insert(AttemptInfo {
            failed: 0,
            blocked_until: None,
        });

        if let Some(until) = entry.blocked_until {
            if std::time::SystemTime::now() < until {
                warn!(email = %payload.email, "login_blocked_memory_rate_limit");
                return Err((
                    StatusCode::TOO_MANY_REQUESTS,
                    "Trop de tentatives, réessaie dans quelques minutes.".to_string(),
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
        .map_err(|_| {
            (
                StatusCode::UNAUTHORIZED,
                "Email ou mot de passe invalide".to_string(),
            )
        })?;

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
        return Err((
            StatusCode::UNAUTHORIZED,
            "Email ou mot de passe invalide".to_string(),
        ));
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
