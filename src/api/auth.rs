use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    body::Body,
    extract::{Request, State},
    http::{
        header::{AUTHORIZATION, CACHE_CONTROL, COOKIE, SET_COOKIE},
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
use serde_json::json;
use sqlx::Row;
use std::{collections::HashMap, sync::Mutex, time::Duration};
use tracing::{info, warn};

use crate::api::audit::audit_log_best_effort;
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
        if let Some(token) = h
            .strip_prefix("Bearer ")
            .or_else(|| h.strip_prefix("bearer "))
        {
            return Some(token.trim().to_string());
        }
    }
    // 2) Cookie: jwt=...
    get_cookie_value(headers, "jwt")
}

/// Utilisé par files/admin/me: extraction email depuis Authorization: Bearer OU cookie jwt
pub fn get_user_from_headers(headers: &HeaderMap) -> Result<String, String> {
    let token = bearer_token(headers)
        .ok_or_else(|| "Auth manquante (Bearer ou cookie jwt)".to_string())?;
    verify_jwt_email(&token)
}

fn cookie_domain_opt() -> Option<String> {
    let d = std::env::var("COOKIE_DOMAIN").ok()?.trim().to_string();
    if d.is_empty() { None } else { Some(d) }
}

/// Par défaut: Secure ON (prod). Tu peux désactiver en dev via COOKIE_SECURE=0.
fn cookie_secure_enabled() -> bool {
    match std::env::var("COOKIE_SECURE").ok().as_deref() {
        Some("0") | Some("false") | Some("no") => false,
        _ => true,
    }
}

fn build_jwt_cookie(token: &str, max_age_secs: i64) -> String {
    // Domain commun aux sous-domaines (jsecure-cloud.com + upload.jsecure-cloud.com)
    let domain = std::env::var("COOKIE_DOMAIN")
        .unwrap_or_else(|_| ".jsecure-cloud.com".to_string())
        .trim()
        .to_string();

    // IMPORTANT pour cross-site fetch avec credentials:
    // SameSite=None + Secure
    format!(
        "jwt={}; Path=/; HttpOnly; SameSite=None; Secure; Max-Age={}; Domain={}",
        token, max_age_secs, domain
    )
}


fn build_delete_cookie() -> String {
    // IMPORTANT: pour supprimer un cookie avec Domain, il faut renvoyer le même Domain.
    let mut s = "jwt=; Path=/; HttpOnly; SameSite=None; Max-Age=0".to_string();
    if let Some(domain) = cookie_domain_opt() {
        s.push_str(&format!("; Domain={}", domain));
    }
    if cookie_secure_enabled() {
        s.push_str("; Secure");
    }
    s
}

// =====================
// IP helper
// =====================
fn client_ip(headers: &HeaderMap) -> String {
    if let Some(v) = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
    {
        return v.trim().to_string();
    }
    if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        return v
            .split(',')
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string();
    }
    "unknown".to_string()
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
    pub token: Option<String>, // cookie only
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
// HANDLER : /auth/login (COOKIE)
// ================================
pub async fn login_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<LoginPayload>,
) -> ApiResult<Response> {
    rate_limit_or_err(&headers, "login", 10, Duration::from_secs(60))?;

    let email_in = payload.email.trim().to_lowercase();
    let password_in = payload.password;

    if email_in.is_empty() || password_in.is_empty() {
        return Err(ApiError::bad_request("email + mot de passe requis"));
    }

    let ip = client_ip(&headers);

    // Anti brute-force mémoire (par email) — IMPORTANT: lock NE DOIT PAS survivre à un await
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
        audit_log_best_effort(
            &state.db,
            Some(&email_in),
            "login",
            None,
            &ip,
            "blocked",
            json!({ "reason": "user_blocked_db" }),
        )
        .await;
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
        audit_log_best_effort(
            &state.db,
            Some(&email_in),
            "login",
            None,
            &ip,
            "fail",
            json!({ "reason": "invalid_credentials" }),
        )
        .await;
        return Err(ApiError::unauthorized_msg("Email ou mot de passe invalide"));
    }

    let token = create_jwt(&email_db)?;

    // ✅ UN SEUL système cookie : helpers
    let cookie = build_jwt_cookie(&token, 60 * 60 * 24);

    let mut resp = Json(AuthResponse {
        status: "ok".to_string(),
        message: "Connexion réussie".to_string(),
        email: Some(email_db.clone()),
        token: None,
    })
    .into_response();

    resp.headers_mut().insert(SET_COOKIE, cookie.parse().unwrap());
    resp.headers_mut().insert(CACHE_CONTROL, "no-store".parse().unwrap());

    audit_log_best_effort(&state.db, Some(&email_db), "login", None, &ip, "ok", json!({})).await;
    info!(email = %email_in, "login_ok");

    Ok(resp)
}

// ================================
// HANDLER : /auth/logout (COOKIE)
// ================================
pub async fn logout_handler(headers: HeaderMap, State(state): State<AppState>) -> ApiResult<Response> {
    let ip = client_ip(&headers);

    // ✅ UN SEUL système cookie : helpers
    let cookie = build_delete_cookie();

    let mut resp = Json(json!({"status":"ok","message":"logout"})).into_response();
    resp.headers_mut().insert(SET_COOKIE, cookie.parse().unwrap());
    resp.headers_mut().insert(CACHE_CONTROL, "no-store".parse().unwrap());

    audit_log_best_effort(&state.db, None, "logout", None, &ip, "ok", json!({})).await;
    Ok(resp)
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

#[derive(serde::Serialize)]
pub struct MeResponse {
    pub status: String,
    pub email: String,
    pub is_admin: bool,

    // quota/usage
    pub quota_bytes: Option<i64>, // valeur DB (ex: 12 GB), ou null si non défini
    pub used_bytes: i64,
    pub max_bytes: i64,
    pub used_percent: f64,
    pub files_count: i64,
}

pub async fn me_handler(headers: HeaderMap, State(state): State<AppState>) -> ApiResult<Json<MeResponse>> {
    let ip = client_ip(&headers);

    let email_raw =
        get_user_from_headers(&headers).map_err(|_| ApiError::unauthorized_msg("Non authentifié"))?;
    let email = email_raw.trim().to_lowercase();

    // 1) user row: id + blocked + admin + quota
    let row_user = sqlx::query(
        r#"
        SELECT
            id,
            COALESCE(is_blocked, 0) as is_blocked,
            COALESCE(is_admin, 0)   as is_admin,
            quota_bytes
        FROM users
        WHERE lower(email) = lower(?1)
        LIMIT 1
        "#,
    )
    .bind(&email)
    .fetch_one(&state.db)
    .await
    .map_err(|_| ApiError::unauthorized_msg("Non authentifié"))?;

    let user_id: i64 = row_user.try_get("id").unwrap_or(0);
    let is_blocked: i64 = row_user.try_get("is_blocked").unwrap_or(0);
    if is_blocked == 1 {
        warn!(%ip, owner=%email, "me_blocked_user");
        return Err(ApiError::forbidden("account blocked"));
    }

    let is_admin_i64: i64 = row_user.try_get("is_admin").unwrap_or(0);
    let is_admin = is_admin_i64 == 1;

    // quota_bytes (peut être NULL)
    let quota_bytes: Option<i64> = row_user.try_get("quota_bytes").ok().filter(|v| *v > 0);

    // 2) stats via files.user_id
    let row_stats = sqlx::query(
        r#"
        SELECT
          COALESCE(SUM(size_bytes), 0) as used_bytes,
          COUNT(*) as files_count
        FROM files
        WHERE user_id = ?1
        "#,
    )
    .bind(user_id)
    .fetch_one(&state.db)
    .await
    .map_err(|e| db_err("me stats", e))?;

    let used_bytes: i64 = row_stats.try_get("used_bytes").unwrap_or(0);
    let files_count: i64 = row_stats.try_get("files_count").unwrap_or(0);

    // 3) max_bytes = quota DB si présent, sinon fallback env
    let fallback: i64 = std::env::var("MAX_STORAGE_PER_USER_BYTES")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(1024 * 1024 * 1024); // 1 GiB défaut

    let max_bytes = quota_bytes.unwrap_or(fallback);

    let used_percent = if max_bytes > 0 {
        (used_bytes as f64 / max_bytes as f64) * 100.0
    } else {
        0.0
    };

    info!(
        %ip,
        owner=%email,
        user_id,
        is_admin,
        used_bytes,
        max_bytes,
        files_count,
        "me_ok"
    );

    Ok(Json(MeResponse {
        status: "ok".to_string(),
        email,
        is_admin,
        quota_bytes,
        used_bytes,
        max_bytes,
        used_percent,
        files_count,
    }))
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
