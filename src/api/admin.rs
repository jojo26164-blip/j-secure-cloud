use axum::{
    extract::{Path, State},
    http::HeaderMap,
    Json,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::Row;
use tracing::{error, info, warn};

use crate::api::auth::get_user_from_headers;
use crate::api::error::{ApiError, ApiResult};
use crate::api::AppState;

// -----------------------------
// Helpers
// -----------------------------
fn client_ip(headers: &HeaderMap) -> String {
    if let Some(v) = headers.get("cf-connecting-ip").and_then(|v| v.to_str().ok()) {
        return v.trim().to_string();
    }
    if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        return v.split(',').next().unwrap_or("unknown").trim().to_string();
    }
    "unknown".to_string()
}

// Fallback env: ADMIN_EMAILS="a@b.com,c@d.com"
fn is_admin_env(email: &str) -> bool {
    let email_lc = email.trim().to_lowercase();
    if email_lc.is_empty() {
        return false;
    }
    let admins = std::env::var("ADMIN_EMAILS").unwrap_or_default();
    admins
        .split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .any(|a| a == email_lc)
}

// ✅ Source de vérité: DB (users.is_admin)
async fn is_admin_db(state: &AppState, email: &str) -> bool {
    let row = sqlx::query(
        r#"
        SELECT COALESCE(is_admin,0) AS is_admin
        FROM users
        WHERE lower(email)=lower(?1)
        LIMIT 1
        "#
    )
    .bind(email)
    .fetch_optional(&state.db)
    .await;

    match row {
        Ok(Some(r)) => r.try_get::<i64, _>("is_admin").unwrap_or(0) == 1,
        _ => false,
    }
}

async fn audit_admin(
    state: &AppState,
    admin_email: &str,
    action: &str,
    target_email: Option<&str>,
    ip: &str,
    meta: serde_json::Value,
) {
    // Best-effort: ne bloque pas l'API si la table n'existe pas
    let _ = sqlx::query(
        r#"
        INSERT INTO admin_audit (admin_email, action, target_email, ip, meta_json)
        VALUES (?1, ?2, ?3, ?4, ?5)
        "#
    )
    .bind(admin_email)
    .bind(action)
    .bind(target_email.map(|s| s.trim().to_lowercase()))
    .bind(ip)
    .bind(meta.to_string())
    .execute(&state.db)
    .await;
}

// Vérif admin standard (DB d’abord, sinon ENV)
async fn require_admin(state: &AppState, headers: &HeaderMap) -> ApiResult<String> {
    let email = get_user_from_headers(headers)
        .map_err(|_| ApiError::unauthorized())?;

    // Logs utiles
    info!("ADMIN CHECK email={}", email);

    let ok = is_admin_db(state, &email).await || is_admin_env(&email);
    if !ok {
        return Err(ApiError::forbidden("admin only"));
    }
    Ok(email)
}

// -----------------------------
// /admin/stats
// -----------------------------
#[derive(Serialize)]
pub struct AdminStatsResponse {
    pub users_count: i64,
    pub files_count: i64,
    pub total_bytes: i64,
}

pub async fn stats_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> ApiResult<Json<AdminStatsResponse>> {
    let ip = client_ip(&headers);
    let admin_email = require_admin(&state, &headers).await
        .map_err(|e| { warn!(%ip, "admin_stats_forbidden"); e })?;

    let users_count: i64 = sqlx::query("SELECT COUNT(*) as cnt FROM users")
        .fetch_one(&state.db)
        .await
        .map(|row| row.try_get::<i64, _>("cnt").unwrap_or(0))
        .map_err(|e| {
            error!(%ip, owner=%admin_email, error=%e, "admin_stats_users_db_error");
            ApiError::internal()
        })?;

    let (files_count, total_bytes): (i64, i64) =
        sqlx::query("SELECT COUNT(*) as cnt, COALESCE(SUM(size_bytes),0) as sum FROM files")
            .fetch_one(&state.db)
            .await
            .map(|row| {
                let cnt = row.try_get::<i64, _>("cnt").unwrap_or(0);
                let sum = row.try_get::<i64, _>("sum").unwrap_or(0);
                (cnt, sum)
            })
            .map_err(|e| {
                error!(%ip, owner=%admin_email, error=%e, "admin_stats_files_db_error");
                ApiError::internal()
            })?;

    info!(%ip, owner=%admin_email, users_count, files_count, total_bytes, "admin_stats_ok");
    Ok(Json(AdminStatsResponse { users_count, files_count, total_bytes }))
}

// -----------------------------
// /admin/users
// -----------------------------
#[derive(Serialize)]
pub struct AdminUserRow {
    pub id: i64,
    pub email: String,
    pub is_admin: i64,
    pub is_blocked: i64,
    pub quota_bytes: Option<i64>,
}

pub async fn users_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<AdminUserRow>>> {
    let ip = client_ip(&headers);
    let admin_email = require_admin(&state, &headers).await
        .map_err(|e| { warn!(%ip, "admin_users_forbidden"); e })?;

    let rows = sqlx::query(
        r#"
        SELECT
            id,
            email,
            COALESCE(is_admin,0) as is_admin,
            COALESCE(is_blocked,0) as is_blocked,
            quota_bytes
        FROM users
        ORDER BY id DESC
        LIMIT 200
        "#
    )
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        error!(%ip, owner=%admin_email, error=%e, "admin_users_db_error");
        ApiError::internal()
    })?;

    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(AdminUserRow {
            id: row.try_get("id").unwrap_or(0),
            email: row.try_get("email").unwrap_or_default(),
            is_admin: row.try_get("is_admin").unwrap_or(0),
            is_blocked: row.try_get("is_blocked").unwrap_or(0),
            quota_bytes: row.try_get("quota_bytes").ok(),
        });
    }

    info!(%ip, owner=%admin_email, users_count=out.len(), "admin_users_ok");
    Ok(Json(out))
}

// -----------------------------
// /admin/users/:email/block
// -----------------------------
#[derive(Serialize)]
pub struct AdminOkResponse {
    pub status: &'static str,
    pub message: String,
}

pub async fn block_user_handler(
    headers: HeaderMap,
    Path(email_to_block): Path<String>,
    State(state): State<AppState>,
) -> ApiResult<Json<AdminOkResponse>> {
    let ip = client_ip(&headers);
    let admin_email = require_admin(&state, &headers).await?;

    let target = email_to_block.trim().to_lowercase();
    if target.is_empty() {
        return Err(ApiError::bad_request("email vide"));
    }
    if target == admin_email.trim().to_lowercase() {
        return Err(ApiError::bad_request("tu ne peux pas te bloquer toi-même"));
    }

    let result = sqlx::query(
        r#"
        UPDATE users
        SET is_blocked = 1
        WHERE lower(email) = ?1
        "#
    )
    .bind(&target)
    .execute(&state.db)
    .await
    .map_err(|e| {
        error!(%ip, owner=%admin_email, target=%target, error=%e, "admin_block_db_error");
        ApiError::internal()
    })?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("user introuvable"));
    }

    audit_admin(&state, &admin_email, "block_user", Some(&target), &ip, json!({})).await;
    Ok(Json(AdminOkResponse { status: "ok", message: format!("user bloqué: {target}") }))
}

// -----------------------------
// /admin/users/:email/unblock
// -----------------------------
pub async fn unblock_user_handler(
    headers: HeaderMap,
    Path(email_to_unblock): Path<String>,
    State(state): State<AppState>,
) -> ApiResult<Json<AdminOkResponse>> {
    let ip = client_ip(&headers);
    let admin_email = require_admin(&state, &headers).await?;

    let target = email_to_unblock.trim().to_lowercase();
    if target.is_empty() {
        return Err(ApiError::bad_request("email vide"));
    }

    let result = sqlx::query(
        r#"
        UPDATE users
        SET is_blocked = 0
        WHERE lower(email) = ?1
        "#
    )
    .bind(&target)
    .execute(&state.db)
    .await
    .map_err(|e| {
        error!(%ip, owner=%admin_email, target=%target, error=%e, "admin_unblock_db_error");
        ApiError::internal()
    })?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("user introuvable"));
    }

    audit_admin(&state, &admin_email, "unblock_user", Some(&target), &ip, json!({})).await;
    Ok(Json(AdminOkResponse { status: "ok", message: format!("user débloqué: {target}") }))
}

// -----------------------------
// /admin/users/:email/quota
// -----------------------------
#[derive(Deserialize)]
pub struct SetQuotaPayload {
    pub quota_bytes: Option<i64>,
}

pub async fn set_quota_handler(
    headers: HeaderMap,
    Path(email_target): Path<String>,
    State(state): State<AppState>,
    Json(payload): Json<SetQuotaPayload>,
) -> ApiResult<Json<AdminOkResponse>> {
    let ip = client_ip(&headers);
    let admin_email = require_admin(&state, &headers).await?;

    let target = email_target.trim().to_lowercase();
    if target.is_empty() {
        return Err(ApiError::bad_request("email vide"));
    }
    if let Some(q) = payload.quota_bytes {
        if q < 0 {
            return Err(ApiError::bad_request("quota_bytes doit être >= 0"));
        }
    }

    let result = sqlx::query(
        r#"
        UPDATE users
        SET quota_bytes = ?1
        WHERE lower(email) = ?2
        "#
    )
    .bind(payload.quota_bytes)
    .bind(&target)
    .execute(&state.db)
    .await
    .map_err(|e| {
        error!(%ip, owner=%admin_email, target=%target, error=%e, "admin_quota_db_error");
        ApiError::internal()
    })?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("user introuvable"));
    }

    audit_admin(
        &state,
        &admin_email,
        "set_quota",
        Some(&target),
        &ip,
        json!({ "quota_bytes": payload.quota_bytes }),
    )
    .await;

    Ok(Json(AdminOkResponse {
        status: "ok",
        message: match payload.quota_bytes {
            Some(q) => format!("quota mis à jour: {target} => {q} bytes"),
            None => format!("quota supprimé (NULL): {target}"),
        },
    }))
}
