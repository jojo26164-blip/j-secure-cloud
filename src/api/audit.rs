use serde_json::Value;
use sqlx::SqlitePool;
use tracing::warn;

use crate::api::error::ApiError;

/// Audit log "best-effort": ne doit JAMAIS casser l'API.
pub async fn audit_log_best_effort(
    db: &SqlitePool,
    actor_email: Option<&str>,
    action: &str,
    target: Option<&str>,
    ip: &str,
    status: &str, // "ok" | "fail"
    meta: Value,
) {
    let actor = actor_email.map(|s| s.trim().to_lowercase());
    let target = target.map(|s| s.trim().to_string());

    let q = sqlx::query(
        r#"
        INSERT INTO audit_logs (actor_email, action, target, ip, status, meta_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
    )
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(ip)
    .bind(status)
    .bind(meta.to_string());

    if let Err(e) = q.execute(db).await {
        // Best-effort: on log seulement.
        warn!(error=%e, action=%action, "audit_log_insert_failed");
    }
}

/// Variante "strict" si un jour tu en as besoin (rare).
pub async fn audit_log_strict(
    db: &SqlitePool,
    actor_email: Option<&str>,
    action: &str,
    target: Option<&str>,
    ip: &str,
    status: &str,
    meta: Value,
) -> Result<(), ApiError> {
    let actor = actor_email.map(|s| s.trim().to_lowercase());
    let target = target.map(|s| s.trim().to_string());

    sqlx::query(
        r#"
        INSERT INTO audit_logs (actor_email, action, target, ip, status, meta_json)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
    )
    .bind(actor)
    .bind(action)
    .bind(target)
    .bind(ip)
    .bind(status)
    .bind(meta.to_string())
    .execute(db)
    .await
    .map_err(|_| ApiError::internal())?;

    Ok(())
}
