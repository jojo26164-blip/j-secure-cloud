use axum::{
    extract::{Multipart, Path as AxumPath, State},
    http::{
        header::{
            ACCEPT_RANGES, CONTENT_DISPOSITION, CONTENT_LENGTH, CONTENT_RANGE, CONTENT_TYPE, RANGE,
        },
        HeaderMap, HeaderValue, StatusCode,
    },
    response::Response,
    Json,
};
use futures_util::{StreamExt, TryStreamExt};
use nix::sys::statvfs::statvfs;
use serde::Serialize;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool};
use std::{
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    fs::File,
    io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt},
    net::UnixStream,
    time::timeout,
};
use tokio_util::io::ReaderStream;
use tracing::{error, warn, info};

use crate::api::{
    audit::audit_log_best_effort,
    auth::get_user_from_headers,
    error::{ApiError, ApiResult},
    rate_limit::rate_limit_or_err,
    AppState,
};

// ======================================================
// DTOs
// ======================================================
#[derive(Serialize, Clone)]
pub struct FileRow {
    pub id: String, // ✅ file_id (stable, public API id)
    pub filename: String,
    pub size_bytes: i64,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct ListFilesResponse {
    pub status: String,
    pub files: Vec<FileRow>,
}

#[derive(Serialize)]
pub struct UploadResponse {
    pub status: String,
    pub message: String,
    pub filename: String, // stored
    pub size_bytes: i64,
}

#[derive(Serialize)]
pub struct OkResponse {
    pub status: &'static str,
    pub message: String,
}

// ======================================================
// Helpers: dirs / ip / filename
// ======================================================
fn uploads_dir() -> PathBuf {
    std::env::var("UPLOAD_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("uploads"))
}

fn tmp_dir() -> PathBuf {
    std::env::var("UPLOAD_TMP_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| uploads_dir().join("tmp"))
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

fn rand_suffix() -> String {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{n}")
}

fn sanitize_filename(name: &str) -> String {
    let base = Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("upload.bin");

    let mut out = String::with_capacity(base.len());
    for c in base.chars() {
        if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "upload.bin".to_string()
    } else {
        out
    }
}

/// Convertit "12345-fichier.pdf" => "fichier.pdf"
fn display_filename(stored: &str) -> String {
    stored
        .splitn(2, '-')
        .nth(1)
        .unwrap_or(stored)
        .replace('"', "")
}

fn guess_content_type(filename: &str) -> &'static str {
    let f = filename.to_lowercase();
    if f.ends_with(".pdf") {
        "application/pdf"
    } else if f.ends_with(".png") {
        "image/png"
    } else if f.ends_with(".jpg") || f.ends_with(".jpeg") {
        "image/jpeg"
    } else if f.ends_with(".webp") {
        "image/webp"
    } else if f.ends_with(".gif") {
        "image/gif"
    } else if f.ends_with(".mp4") {
        "video/mp4"
    } else if f.ends_with(".mp3") {
        "audio/mpeg"
    } else if f.ends_with(".zip") {
        "application/zip"
    } else if f.ends_with(".iso") {
        "application/x-iso9660-image"
    } else {
        "application/octet-stream"
    }
}

// ======================================================
// Limits (IMPORTANT)
// ======================================================
fn max_upload_bytes() -> u64 {
    std::env::var("MAX_UPLOAD_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(6_u64 * 1024 * 1024 * 1024) // 6 GiB default
}

fn min_free_bytes() -> u64 {
    std::env::var("MIN_FREE_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2_u64 * 1024 * 1024 * 1024) // 2 GiB default
}

fn is_forbidden_extension(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    let forbidden = [".exe", ".dll", ".bat", ".cmd", ".msi", ".ps1"];
    forbidden.iter().any(|ext| lower.ends_with(ext))
}

fn audit_meta_err(msg: &str) -> serde_json::Value {
    serde_json::json!({ "error": msg })
}

// ======================================================
// DB helpers: blocked + quota + used + user_id
// ======================================================
async fn ensure_not_blocked(db: &SqlitePool, email: &str) -> Result<(), ApiError> {
    let row = sqlx::query(
        r#"SELECT COALESCE(is_blocked, 0) as b
           FROM users
           WHERE lower(email) = lower(?1)
           LIMIT 1"#,
    )
    .bind(email)
    .fetch_one(db)
    .await
    .map_err(|_| ApiError::unauthorized())?;

    let b: i64 = row.try_get("b").unwrap_or(0);
    if b == 1 {
        return Err(ApiError::forbidden("account blocked"));
    }
    Ok(())
}

async fn get_user_id(db: &SqlitePool, email: &str) -> Result<i64, ApiError> {
    let row = sqlx::query(
        r#"SELECT id
           FROM users
           WHERE lower(email) = lower(?1)
           LIMIT 1"#,
    )
    .bind(email)
    .fetch_one(db)
    .await
    .map_err(|_| ApiError::unauthorized())?;

    Ok(row.try_get::<i64, _>("id").unwrap_or(0))
}

async fn get_user_quota_bytes(db: &SqlitePool, email: &str) -> Result<i64, ApiError> {
    let fallback: i64 = std::env::var("MAX_STORAGE_PER_USER_BYTES")
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .unwrap_or(1024 * 1024 * 1024); // 1GiB

    let row_notice = sqlx::query(
        r#"SELECT quota_bytes
           FROM users
           WHERE lower(email) = lower(?1)
           LIMIT 1"#,
    )
    .bind(email)
    .fetch_optional(db)
    .await
    .map_err(|_| ApiError::internal())?;

    if let Some(row) = row_notice {
        let q: Option<i64> = row.try_get("quota_bytes").ok();
        let q = q.filter(|v| *v > 0);
        Ok(q.unwrap_or(fallback))
    } else {
        Ok(fallback)
    }
}

/// NOTE: on compte tout (y compris corbeille).
/// Si tu veux libérer quota au moment "delete => trash", change WHERE deleted_at IS NULL.
async fn get_used_bytes(db: &SqlitePool, user_id: i64) -> Result<i64, ApiError> {
    let (used,): (i64,) =
        sqlx::query_as(r#"SELECT COALESCE(SUM(size_bytes), 0) FROM files WHERE user_id = ?1"#)
            .bind(user_id)
            .fetch_one(db)
            .await
            .map_err(|_| ApiError::internal())?;
    Ok(used)
}

// ======================================================
// ClamAV scan (best-effort)
// ======================================================
async fn scan_file_with_clamav(path: &Path) -> Result<(), String> {
    if std::env::var("CLAMD_DISABLED").unwrap_or_default() == "1" {
        return Ok(());
    }

    let sock =
        std::env::var("CLAMD_SOCKET").unwrap_or_else(|_| "/run/clamav/clamd.ctl".to_string());

    let mut stream = UnixStream::connect(&sock)
        .await
        .map_err(|e| format!("cannot connect clamd socket {sock}: {e}"))?;

    let p = path
        .to_str()
        .ok_or_else(|| "invalid path (utf8)".to_string())?;
    let cmd = format!("SCAN {}\n", p);

    stream
        .write_all(cmd.as_bytes())
        .await
        .map_err(|e| format!("clamd write error: {e}"))?;

    let mut out: Vec<u8> = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];

    timeout(Duration::from_secs(60), async {
        loop {
            let n = stream
                .read(&mut buf)
                .await
                .map_err(|e| format!("clamd read error: {e}"))?;
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);

            let s = String::from_utf8_lossy(&out);
            if s.contains("OK") || s.contains("FOUND") || s.contains("ERROR") {
                break;
            }
            if out.len() > 64 * 1024 {
                break;
            }
        }
        Ok::<(), String>(())
    })
    .await
    .map_err(|_| "clamd timeout".to_string())??;

    let resp = String::from_utf8_lossy(&out).trim().to_string();
    if resp.is_empty() {
        return Err("clamd empty response".to_string());
    }
    if resp.contains("FOUND") {
        Err(resp)
    } else if resp.contains("OK") {
        Ok(())
    } else {
        Err(resp)
    }
}

// ======================================================
// Range parsing
// ======================================================
#[derive(Debug, Clone, Copy)]
struct ByteRange {
    start: u64,
    end_inclusive: u64,
}

fn parse_range_header(range: &str, file_size: u64) -> Option<ByteRange> {
    if file_size == 0 {
        return None;
    }
    let s = range.trim();
    if !s.to_ascii_lowercase().starts_with("bytes=") {
        return None;
    }
    let part = s.splitn(2, '=').nth(1)?.trim();
    if part.contains(',') {
        return None; // pas multi-range
    }
    let (a, b) = part.split_once('-')?;
    let a = a.trim();
    let b = b.trim();

    if a.is_empty() {
        // suffix bytes: "-500"
        let suffix = b.parse::<u64>().ok()?;
        if suffix == 0 {
            return None;
        }
        let suffix = suffix.min(file_size);
        let start = file_size - suffix;
        let end = file_size - 1;
        return Some(ByteRange {
            start,
            end_inclusive: end,
        });
    }

    let start = a.parse::<u64>().ok()?;
    if start >= file_size {
        return None;
    }

    let end_inclusive = if b.is_empty() {
        file_size - 1
    } else {
        let end = b.parse::<u64>().ok()?;
        if end < start {
            return None;
        }
        end.min(file_size - 1)
    };

    Some(ByteRange { start, end_inclusive })
}

// ======================================================
// Handlers
// ======================================================

// GET /api/files
pub async fn list_files_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> ApiResult<Json<ListFilesResponse>> {
    let ip = client_ip(&headers);

    let owner_email = match get_user_from_headers(&headers) {
        Ok(e) => e.trim().to_lowercase(),
        Err(msg) => {
            audit_log_best_effort(
                &state.db,
                None,
                "list_files",
                None,
                &ip,
                "fail",
                audit_meta_err(&msg),
            )
            .await;
            return Err(ApiError::unauthorized());
        }
    };

    ensure_not_blocked(&state.db, &owner_email).await?;
    let user_id = get_user_id(&state.db, &owner_email).await?;

    let rows = sqlx::query(
        r#"
        SELECT file_id, filename, size_bytes, created_at
        FROM files
        WHERE user_id = ?1
          AND deleted_at IS NULL
        ORDER BY created_at DESC
        LIMIT 500
        "#,
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| ApiError::internal())?;

    let mut files = Vec::with_capacity(rows.len());
    for r in rows {
        files.push(FileRow {
            id: r.try_get("file_id").unwrap_or_default(),
            filename: r.try_get("filename").unwrap_or_default(),
            size_bytes: r.try_get("size_bytes").unwrap_or(0),
            created_at: r.try_get("created_at").unwrap_or_default(),
        });
    }

    Ok(Json(ListFilesResponse {
        status: "ok".to_string(),
        files,
    }))
}

// POST /api/files/upload
pub async fn upload_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> ApiResult<Json<UploadResponse>> {
    let ip = client_ip(&headers);

    // Rate limit upload
    if let Err(e) = rate_limit_or_err(&headers, "upload", 30, Duration::from_secs(60)) {
        audit_log_best_effort(
            &state.db,
            None,
            "upload",
            None,
            &ip,
            "denied",
            serde_json::json!({ "reason": "rate_limited", "where": "upload" }),
        )
        .await;
        return Err(e);
    }

    // Auth
    let owner_email = match get_user_from_headers(&headers) {
        Ok(email) => email.trim().to_lowercase(),
        Err(msg) => {
            audit_log_best_effort(
                &state.db,
                None,
                "upload",
                None,
                &ip,
                "fail",
                audit_meta_err(&msg),
            )
            .await;
            return Err(ApiError::unauthorized());
        }
    };

    ensure_not_blocked(&state.db, &owner_email).await?;
    let user_id = get_user_id(&state.db, &owner_email).await?;
    let max_upload = max_upload_bytes();

    // Early reject via content-length (si présent)
    if let Some(cl) = headers.get(CONTENT_LENGTH).and_then(|v| v.to_str().ok()) {
        if let Ok(size) = cl.parse::<u64>() {
            if size > max_upload {
                audit_log_best_effort(
                    &state.db,
                    Some(&owner_email),
                    "upload",
                    None,
                    &ip,
                    "denied",
                    serde_json::json!({
                        "reason": "payload_too_large",
                        "content_length": size,
                        "max_upload": max_upload,
                        "phase": "early_content_length"
                    }),
                )
                .await;
                return Err(ApiError::payload_too_large("fichier trop volumineux"));
            }
        }
    }

    // Quota
    let max_user_storage = get_user_quota_bytes(&state.db, &owner_email).await?;
    let used_bytes = get_used_bytes(&state.db, user_id).await?;

    // Prepare dirs
    let up_dir = uploads_dir();
    tokio::fs::create_dir_all(&up_dir)
        .await
        .map_err(|_| ApiError::internal())?;
    let t_dir = tmp_dir();
    tokio::fs::create_dir_all(&t_dir)
        .await
        .map_err(|_| ApiError::internal())?;

    // Disk free
    let vfs = statvfs(&up_dir).map_err(|_| ApiError::internal())?;
    let free_bytes = (vfs.blocks_available() as u64) * (vfs.block_size() as u64);
    if free_bytes < min_free_bytes() {
        audit_log_best_effort(
            &state.db,
            Some(&owner_email),
            "upload",
            None,
            &ip,
            "denied",
            serde_json::json!({
                "reason": "insufficient_storage",
                "free_bytes": free_bytes,
                "min_free_bytes": min_free_bytes()
            }),
        )
        .await;
        return Err(ApiError::insufficient_storage("espace disque insuffisant"));
    }

    // Read multipart
    let mut original_name: Option<String> = None;
    let mut temp_path: Option<PathBuf> = None;
    let mut final_name: Option<String> = None;
    let mut total_written: u64 = 0;
    let mut sha256_hex: Option<String> = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|_| ApiError::bad_request("Erreur lecture multipart"))?
    {
        if field.name() == Some("file") {
            let fname = field.file_name().unwrap_or("upload.bin").to_string();

            if is_forbidden_extension(&fname) {
                audit_log_best_effort(
                    &state.db,
                    Some(&owner_email),
                    "upload",
                    Some(&fname),
                    &ip,
                    "denied",
                    serde_json::json!({ "reason": "forbidden_extension", "filename": fname }),
                )
                .await;
                return Err(ApiError::file_refused());
            }

            let safe = sanitize_filename(&fname);
            let unique = format!("{}-{}", rand_suffix(), safe);
            let tmp = t_dir.join(format!("{}.part", &unique));

            original_name = Some(fname.clone());
            final_name = Some(unique.clone());
            temp_path = Some(tmp.clone());

            let mut out = tokio::fs::File::create(&tmp)
                .await
                .map_err(|_| ApiError::internal())?;

            let mut hasher = Sha256::new();
            let mut stream = field.into_stream();

            while let Some(chunk_res) = stream.next().await {
                let chunk = chunk_res.map_err(|_| ApiError::bad_request("Erreur chunk upload"))?;

                total_written = total_written.saturating_add(chunk.len() as u64);
                if total_written > max_upload {
                    let _ = tokio::fs::remove_file(&tmp).await;
                    audit_log_best_effort(
                        &state.db,
                        Some(&owner_email),
                        "upload",
                        original_name.as_deref(),
                        &ip,
                        "denied",
                        serde_json::json!({
                            "reason": "payload_too_large",
                            "written": total_written,
                            "max_upload": max_upload
                        }),
                    )
                    .await;
                    return Err(ApiError::payload_too_large("fichier trop volumineux"));
                }

                let projected = used_bytes.saturating_add(total_written as i64);
                if projected > max_user_storage {
                    let _ = tokio::fs::remove_file(&tmp).await;
                    audit_log_best_effort(
                        &state.db,
                        Some(&owner_email),
                        "upload",
                        original_name.as_deref(),
                        &ip,
                        "denied",
                        serde_json::json!({
                            "reason": "quota_exceeded",
                            "used_bytes": used_bytes,
                            "written": total_written,
                            "projected_bytes": projected,
                            "quota_bytes": max_user_storage
                        }),
                    )
                    .await;
                    return Err(ApiError::quota_exceeded("quota de stockage dépassé"));
                }

                hasher.update(&chunk);
                out.write_all(&chunk).await.map_err(|_| ApiError::internal())?;
            }

            out.flush().await.map_err(|_| ApiError::internal())?;
            drop(out);

            sha256_hex = Some(format!("{:x}", hasher.finalize()));

            // ClamAV (si activé)
            if let Err(reason) = scan_file_with_clamav(&tmp).await {
                let _ = tokio::fs::remove_file(&tmp).await;

                if reason.contains("FOUND") {
                    audit_log_best_effort(
                        &state.db,
                        Some(&owner_email),
                        "upload",
                        final_name.as_deref(),
                        &ip,
                        "denied",
                        serde_json::json!({
                            "reason": "virus_detected",
                            "engine": "clamav",
                            "clamav_resp": reason
                        }),
                    )
                    .await;
                    return Err(ApiError::virus_detected());
                }

                audit_log_best_effort(
                    &state.db,
                    Some(&owner_email),
                    "upload",
                    final_name.as_deref(),
                    &ip,
                    "error",
                    serde_json::json!({
                        "reason": "clamav_error",
                        "engine": "clamav",
                        "clamav_resp": reason
                    }),
                )
                .await;

                return Err(ApiError::internal_msg(format!("ClamAV error: {reason}")));
            }

            break;
        }
    }

    let orig = original_name.ok_or_else(|| ApiError::bad_request("Champ 'file' manquant"))?;
    let tmp = temp_path.ok_or_else(ApiError::internal)?;
    let stored = final_name.ok_or_else(ApiError::internal)?;
    let sha256_hex = sha256_hex.unwrap_or_else(|| "0".repeat(64));
    let mime_type = guess_content_type(&orig).to_string();

    // Move tmp -> final
    let final_path = uploads_dir().join(&stored);
    tokio::fs::rename(&tmp, &final_path)
        .await
        .map_err(|_| ApiError::internal())?;

    let size_bytes = total_written as i64;
    let file_id = stored.clone(); // ✅ stable id

    // DB insert
    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO files (user_id, file_id, filename, size_bytes, sha256, mime_type)
        VALUES (?1, ?2, ?3, ?4, ?5, ?6)
        "#,
    )
    .bind(user_id)
    .bind(&file_id)
    .bind(&stored)
    .bind(size_bytes)
    .bind(&sha256_hex)
    .bind(&mime_type)
    .execute(&state.db)
    .await
    {
        error!(error = %e, "upload_db_insert_failed");
        let _ = tokio::fs::remove_file(&final_path).await;

        audit_log_best_effort(
            &state.db,
            Some(&owner_email),
            "upload",
            Some(&stored),
            &ip,
            "fail",
            serde_json::json!({
                "reason": "db_insert_failed",
                "stored": stored
            }),
        )
        .await;

        return Err(ApiError::internal());
    }

    audit_log_best_effort(
        &state.db,
        Some(&owner_email),
        "upload",
        Some(&stored),
        &ip,
        "ok",
        serde_json::json!({
            "original": orig,
            "stored": stored,
            "size_bytes": size_bytes,
            "sha256": sha256_hex,
            "mime_type": mime_type
        }),
    )
    .await;

    info!(owner=%owner_email, file_id=%file_id, size=%size_bytes, "upload_ok");

    Ok(Json(UploadResponse {
        status: "ok".to_string(),
        message: "Fichier uploadé".to_string(),
        filename: file_id,
        size_bytes,
    }))
}

// ============================================================
// GET /api/files/:id/download (streaming + Range + audit)
// :id = file_id (String)
// ============================================================
pub async fn download_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(file_id): AxumPath<String>,
) -> ApiResult<Response> {
    let ip = client_ip(&headers);

    // 1) Auth
    let owner_email = match get_user_from_headers(&headers) {
        Ok(e) => e.trim().to_lowercase(),
        Err(msg) => {
            audit_log_best_effort(
                &state.db,
                None,
                "download",
                Some(&format!("file_id={}", file_id)),
                &ip,
                "fail",
                audit_meta_err(&msg),
            )
            .await;
            return Err(ApiError::unauthorized());
        }
    };

    // 2) Block check
    if let Err(e) = ensure_not_blocked(&state.db, &owner_email).await {
        audit_log_best_effort(
            &state.db,
            Some(&owner_email),
            "download",
            Some(&format!("file_id={}", file_id)),
            &ip,
            "fail",
            serde_json::json!({ "reason": "blocked" }),
        )
        .await;
        return Err(e);
    }

    let requester_user_id = get_user_id(&state.db, &owner_email).await?;

    // 3) DB lookup ✅ file_id + pas dans la corbeille
    let row = match sqlx::query(
        r#"
        SELECT filename, user_id, size_bytes
        FROM files
        WHERE file_id = ?1
          AND deleted_at IS NULL
        LIMIT 1
        "#,
    )
    .bind(&file_id)
    .fetch_optional(&state.db)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            audit_log_best_effort(
                &state.db,
                Some(&owner_email),
                "download",
                Some(&format!("file_id={}", file_id)),
                &ip,
                "fail",
                serde_json::json!({ "reason": "db_not_found" }),
            )
            .await;
            return Err(ApiError::not_found("file introuvable"));
        }
        Err(_) => {
            audit_log_best_effort(
                &state.db,
                Some(&owner_email),
                "download",
                Some(&format!("file_id={}", file_id)),
                &ip,
                "fail",
                serde_json::json!({ "reason": "db_error" }),
            )
            .await;
            return Err(ApiError::internal());
        }
    };

    let stored_name: String = row.try_get("filename").unwrap_or_default();
    let file_user_id: i64 = row.try_get("user_id").unwrap_or(0);

    // 4) Cross-user
    if file_user_id != requester_user_id {
        audit_log_best_effort(
            &state.db,
            Some(&owner_email),
            "download",
            Some(&format!("file_id={}", file_id)),
            &ip,
            "fail",
            serde_json::json!({ "reason": "forbidden_cross_user" }),
        )
        .await;
        return Err(ApiError::forbidden("cross-user access"));
    }

    // 5) Disk metadata
    let path = uploads_dir().join(&stored_name);
    let meta = match tokio::fs::metadata(&path).await {
        Ok(m) => m,
        Err(_) => {
            audit_log_best_effort(
                &state.db,
                Some(&owner_email),
                "download",
                Some(&format!("file_id={}", file_id)),
                &ip,
                "fail",
                serde_json::json!({ "reason": "disk_missing", "stored": stored_name }),
            )
            .await;
            return Err(ApiError::not_found("fichier manquant sur disque"));
        }
    };

    let file_size = meta.len();

    // Nom affiché
    let display = display_filename(&stored_name);
    let ct = guess_content_type(&display);
    let cd = format!("attachment; filename=\"{}\"", display);

    // 6) Open file
    let mut file = match File::open(&path).await {
        Ok(f) => f,
        Err(_) => {
            audit_log_best_effort(
                &state.db,
                Some(&owner_email),
                "download",
                Some(&format!("file_id={}", file_id)),
                &ip,
                "fail",
                serde_json::json!({ "reason": "open_failed", "stored": stored_name }),
            )
            .await;
            return Err(ApiError::not_found("fichier non lisible"));
        }
    };

    // 7) Range handling
    if let Some(rh) = headers.get(RANGE).and_then(|v| v.to_str().ok()) {
        if let Some(br) = parse_range_header(rh, file_size) {
            let start = br.start;
            let end = br.end_inclusive;
            let len = (end - start) + 1;

            file.seek(std::io::SeekFrom::Start(start))
                .await
                .map_err(|_| ApiError::internal())?;

            let limited = file.take(len);
            let stream = ReaderStream::new(limited);
            let body = axum::body::Body::from_stream(stream);

            let mut resp = Response::new(body);
            *resp.status_mut() = StatusCode::PARTIAL_CONTENT;

            let cr = format!("bytes {}-{}/{}", start, end, file_size);

            resp.headers_mut()
                .insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
            resp.headers_mut()
                .insert(CONTENT_RANGE, HeaderValue::from_str(&cr).unwrap());
            resp.headers_mut().insert(
                CONTENT_LENGTH,
                HeaderValue::from_str(&len.to_string()).unwrap(),
            );
            resp.headers_mut()
                .insert(CONTENT_DISPOSITION, HeaderValue::from_str(&cd).unwrap());
            resp.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static(ct));

            audit_log_best_effort(
                &state.db,
                Some(&owner_email),
                "download",
                Some(&format!("file_id={}", file_id)),
                &ip,
                "ok",
                serde_json::json!({
                    "stored": stored_name,
                    "display": display,
                    "file_size": file_size,
                    "range": rh,
                    "start": start,
                    "end": end,
                    "status": 206
                }),
            )
            .await;

            return Ok(resp);
        } else {
            let mut resp = Response::new(axum::body::Body::empty());
            *resp.status_mut() = StatusCode::RANGE_NOT_SATISFIABLE;

            resp.headers_mut()
                .insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
            resp.headers_mut().insert(
                CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes */{}", file_size)).unwrap(),
            );
            resp.headers_mut()
                .insert(CONTENT_DISPOSITION, HeaderValue::from_str(&cd).unwrap());
            resp.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static(ct));

            audit_log_best_effort(
                &state.db,
                Some(&owner_email),
                "download",
                Some(&format!("file_id={}", file_id)),
                &ip,
                "fail",
                serde_json::json!({
                    "reason": "range_invalid",
                    "range": rh,
                    "file_size": file_size,
                    "status": 416
                }),
            )
            .await;

            return Ok(resp);
        }
    }

    // 8) Full download
    let stream = ReaderStream::new(file);
    let body = axum::body::Body::from_stream(stream);

    let mut resp = Response::new(body);
    *resp.status_mut() = StatusCode::OK;

    resp.headers_mut()
        .insert(ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    resp.headers_mut().insert(
        CONTENT_LENGTH,
        HeaderValue::from_str(&file_size.to_string()).unwrap(),
    );
    resp.headers_mut()
        .insert(CONTENT_DISPOSITION, HeaderValue::from_str(&cd).unwrap());
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static(ct));

    audit_log_best_effort(
        &state.db,
        Some(&owner_email),
        "download",
        Some(&format!("file_id={}", file_id)),
        &ip,
        "ok",
        serde_json::json!({
            "stored": stored_name,
            "display": display,
            "file_size": file_size,
            "status": 200
        }),
    )
    .await;

    Ok(resp)
}

// ============================================================
// DELETE /api/files/:id  => move to trash (soft delete)
// :id = file_id (String)
// ============================================================


pub async fn delete_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(file_id): AxumPath<String>,
) -> ApiResult<Json<OkResponse>> {
    let ip = client_ip(&headers);

    let owner_email = get_user_from_headers(&headers)
        .map_err(|_| ApiError::unauthorized())?
        .trim()
        .to_lowercase();

    ensure_not_blocked(&state.db, &owner_email).await?;
    let user_id = get_user_id(&state.db, &owner_email).await?;

    // 1️⃣ DELETE = mise en corbeille (source de vérité)
    let res = sqlx::query(
        r#"
        UPDATE files
        SET deleted_at = CAST(strftime('%s','now') AS INTEGER)
        WHERE user_id = ?1
          AND file_id = ?2
          AND deleted_at IS NULL
        "#,
    )
    .bind(user_id)
    .bind(&file_id)
    .execute(&state.db)
    .await
    .map_err(|_| ApiError::internal())?;

    // 2️⃣ Cas normal : on vient de le mettre en corbeille
    if res.rows_affected() == 1 {
        info!(owner=%owner_email, file_id=%file_id, "moved_to_trash");

        return Ok(Json(OkResponse {
            status: "ok",
            message: "moved_to_trash".to_string(),
        }));
    }

    // 3️⃣ Si aucune ligne modifiée → soit déjà en trash, soit inexistant
    let exists = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)
        FROM files
        WHERE user_id = ?1 AND file_id = ?2
        "#,
    )
    .bind(user_id)
    .bind(&file_id)
    .fetch_one(&state.db)
    .await
    .map_err(|_| ApiError::internal())?;

    if exists == 0 {
        return Err(ApiError::not_found("file not found"));
    }

    // 4️⃣ Déjà en corbeille → OK silencieux
    Ok(Json(OkResponse {
        status: "ok",
        message: "already_in_trash".to_string(),
    }))
}


// ============================================================
// GET /api/files/trash
// ============================================================
pub async fn trash_list_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<FileRow>>> {
    let owner_email = get_user_from_headers(&headers)
        .map_err(|_| ApiError::unauthorized())?
        .trim()
        .to_lowercase();

    ensure_not_blocked(&state.db, &owner_email).await?;
    let user_id = get_user_id(&state.db, &owner_email).await?;

    let rows = sqlx::query(
        r#"
        SELECT file_id AS id, filename, size_bytes, created_at
        FROM files
        WHERE user_id = ?1 AND deleted_at IS NOT NULL
        ORDER BY deleted_at DESC
        LIMIT 500
        "#,
    )
    .bind(user_id)
    .fetch_all(&state.db)
    .await
    .map_err(|_| ApiError::internal())?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        out.push(FileRow {
            id: r.try_get("id").unwrap_or_else(|_| "".to_string()),
            filename: r.try_get("filename").unwrap_or_default(),
            size_bytes: r.try_get("size_bytes").unwrap_or(0),
            created_at: r.try_get("created_at").unwrap_or_default(),
        });
    }

    Ok(Json(out))
}

// ============================================================
// POST /api/files/:id/restore
// :id = file_id (String)
// ============================================================
pub async fn restore_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(file_id): AxumPath<String>,
) -> ApiResult<Json<OkResponse>> {
    let owner_email = get_user_from_headers(&headers)
        .map_err(|_| ApiError::unauthorized())?
        .trim()
        .to_lowercase();

    ensure_not_blocked(&state.db, &owner_email).await?;
    let user_id = get_user_id(&state.db, &owner_email).await?;

    let r = sqlx::query(
        r#"
        UPDATE files
        SET deleted_at = NULL
        WHERE file_id = ?1 AND user_id = ?2 AND deleted_at IS NOT NULL
        "#,
    )
    .bind(&file_id)
    .bind(user_id)
    .execute(&state.db)
    .await
    .map_err(|_| ApiError::internal())?;

    if r.rows_affected() == 0 {
        return Err(ApiError::not_found("file not found (not in trash)"));
    }

    Ok(Json(OkResponse {
        status: "ok",
        message: "restored".to_string(),
    }))
}

// ============================================================
// DELETE /api/files/:id/purge
// :id = file_id (String)
// ============================================================
pub async fn purge_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(file_id): AxumPath<String>,
) -> ApiResult<Json<OkResponse>> {
    let owner_email = get_user_from_headers(&headers)
        .map_err(|_| ApiError::unauthorized())?
        .trim()
        .to_lowercase();

    ensure_not_blocked(&state.db, &owner_email).await?;
    let user_id = get_user_id(&state.db, &owner_email).await?;

    let row = sqlx::query(
        r#"
        SELECT filename
        FROM files
        WHERE file_id = ?1 AND user_id = ?2 AND deleted_at IS NOT NULL
        LIMIT 1
        "#,
    )
    .bind(&file_id)
    .bind(user_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|_| ApiError::internal())?;

    let Some(row) = row else {
        return Err(ApiError::not_found("file not found (not in trash)"));
    };

    let filename: String = row.try_get("filename").unwrap_or_default();
    let path = uploads_dir().join(&filename);

    // Disk first (best effort), then DB delete
    let disk_res = tokio::fs::remove_file(&path).await;

    let r = sqlx::query(r#"DELETE FROM files WHERE file_id = ?1 AND user_id = ?2"#)
        .bind(&file_id)
        .bind(user_id)
        .execute(&state.db)
        .await
        .map_err(|_| ApiError::internal())?;

    if r.rows_affected() == 0 {
        return Err(ApiError::not_found("file not found"));
    }

    if let Err(e) = disk_res {
        warn!(error=%e, "purge_disk_failed_but_db_removed");
    }

    Ok(Json(OkResponse {
        status: "ok",
        message: format!("purged: {filename}"),
    }))
}
