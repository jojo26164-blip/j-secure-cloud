use axum::{extract::State, Json};
use serde::Serialize;
use std::time::Instant;

use crate::api::error::{ApiError, ApiResult};
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

pub async fn health_handler(State(state): State<AppState>) -> ApiResult<Json<HealthResponse>> {
    // DB check ultra simple
    let db_ok = sqlx::query("SELECT 1").execute(&state.db).await.is_ok();
    let uptime = STARTED_AT.elapsed();

    let resp = HealthResponse {
        status: if db_ok { "ok" } else { "degraded" },
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: uptime.as_secs(),
        db: DbStatus { ok: db_ok },
    };

    // Si DB down: 503 (pro) MAIS en JSON d'erreur uniforme
    if !db_ok {
        return Err(ApiError::new(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "SERVICE_UNAVAILABLE",
            "DB indisponible",
        ));
    }

    Ok(Json(resp))
}
#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::sqlite::SqlitePoolOptions;

    #[tokio::test]
    async fn health_ok_with_in_memory_db() {
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect(":memory:")
            .await
            .unwrap();

        // adapte si ton AppState a un autre champ/nom
        let state = AppState { db };

        let r = health_handler(State(state)).await;
        assert!(r.is_ok());
        let json = r.unwrap();
        assert_eq!(json.status, "ok");
    }
}
