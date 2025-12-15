use axum::{extract::State, http::StatusCode, Json};
use serde::Serialize;
use std::time::{Duration, Instant};

use crate::api::AppState;

// Uptime (depuis le démarrage du process)
static STARTED_AT: once_cell::sync::Lazy<Instant> = once_cell::sync::Lazy::new(Instant::now);

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub version: &'static str,
    pub uptime_seconds: u64,
    pub db: DbStatus,
}

#[derive(Serialize)]
pub struct DbStatus {
    pub ok: bool,
}

pub async fn health_handler(
    State(state): State<AppState>,
) -> Result<Json<HealthResponse>, (StatusCode, String)> {
    // DB check ultra simple
    let db_ok = sqlx::query("SELECT 1")
        .execute(&state.db)
        .await
        .is_ok();

    let uptime = STARTED_AT.elapsed();

    let resp = HealthResponse {
        status: if db_ok { "ok" } else { "degraded" },
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: uptime.as_secs(),
        db: DbStatus { ok: db_ok },
    };

    // Si DB down: on renvoie 503 (pro)
    if !db_ok {
        return Err((StatusCode::SERVICE_UNAVAILABLE, serde_json::to_string(&resp).unwrap()));
    }

    Ok(Json(resp))
}
