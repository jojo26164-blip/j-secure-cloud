use axum::{extract::State, http::HeaderMap, Json};
use serde::Serialize;
use sqlx::Row;
use tracing::{error, info, warn};

use crate::api::auth::get_user_from_headers;
use crate::api::error::{ApiError, ApiResult};
use crate::api::AppState;

#[derive(Serialize)]
pub struct MeResponse {
    pub email: String,
    pub used_bytes: i64,
    pub max_bytes: i64,
    pub used_percent: f64,
    pub files_count: i64,
}

pub async fn me_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> ApiResult<Json<MeResponse>> {
    let ip = client_ip(&headers);

    let email_raw = match get_user_from_headers(&headers) {
        Ok(e) => e,
        Err(msg) => {
            warn!(%ip, %msg, "me_unauthorized");
            return Err(ApiError::unauthorized());
        }
    };

    // Normalisation unique
    let email = email_raw.trim().to_lowercase();

    // (Optionnel mais recommandé) : bloqué => forbidden
    let row_user = sqlx::query(
        r#"
        SELECT
            COALESCE(is_blocked, 0) as is_blocked,
            quota_bytes
        FROM users
        WHERE lower(email) = lower(?1)
        LIMIT 1
        "#,
    )
    .bind(&email)
    .fetch_one(&state.db)
    .await
    .map_err(|_| ApiError::unauthorized())?;

    let is_blocked: i64 = row_user.try_get("is_blocked").unwrap_or(0);
    if is_blocked == 1 {
        warn!(%ip, owner=%email, "me_blocked_user");
        return Err(ApiError::forbidden("account blocked"));
    }

    // used + files_count
    let (used_bytes, files_count) = sqlx::query(
        r#"
        SELECT
          COALESCE(SUM(size_bytes), 0) as used_bytes,
          COUNT(*) as files_count
        FROM files
        WHERE owner = ?1
        "#,
    )
    .bind(&email)
    .fetch_one(&state.db)
    .await
    .map(|row| {
        let used: i64 = row.try_get("used_bytes").unwrap_or(0);
        let cnt: i64 = row.try_get("files_count").unwrap_or(0);
        (used, cnt)
    })
    .map_err(|e| {
        error!(%ip, owner=%email, error=%e, "me_db_error");
        ApiError::internal()
    })?;

    // max_bytes = quota_bytes si défini, sinon fallback env
    let fallback: i64 = std::env::var("MAX_STORAGE_PER_USER_BYTES")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(1024 * 1024 * 1024); // 1 GiB défaut


let quota_db: Option<i64> = row_user.try_get("quota_bytes").ok();
let quota_db = quota_db.filter(|v| *v > 0);
let max_bytes = quota_db.unwrap_or(fallback);

    let used_percent = if max_bytes > 0 {
        (used_bytes as f64 / max_bytes as f64) * 100.0
    } else {
        0.0
    };

    info!(%ip, owner=%email, used_bytes, max_bytes, files_count, "me_ok");

    Ok(Json(MeResponse {
        email,
        used_bytes,
        max_bytes,
        used_percent,
        files_count,
    }))
}

fn client_ip(headers: &HeaderMap) -> String {
    if let Some(v) = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
    {
        return v.trim().to_string();
    }
    if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        return v.split(',').next().unwrap_or("unknown").trim().to_string();
    }
    "unknown".to_string()
}
