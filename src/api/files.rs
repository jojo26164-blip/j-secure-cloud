use axum::{
    body::Body,
    extract::{Multipart, Path as AxumPath, State},
    http::{header::CONTENT_LENGTH, HeaderMap, StatusCode},
    response::Response,
    Json,
};
use nix::sys::statvfs::statvfs;
use sqlx::Row;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tracing::{error, info, warn};

use crate::api::auth::get_user_from_headers;
use crate::api::error::{ApiError, ApiResult};
use crate::api::rate_limit::rate_limit_or_err;
use crate::api::AppState;

// ======================
// Helpers
// ======================

fn uploads_dir() -> PathBuf {
    std::env::var("UPLOAD_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("uploads"))
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

fn is_forbidden_extension(filename: &str) -> bool {
    let lower = filename.to_lowercase();
    let forbidden = [".exe", ".dll", ".bat", ".cmd", ".sh", ".msi", ".ps1"];
    forbidden.iter().any(|ext| lower.ends_with(ext))
}

fn basic_malware_scan(filename: &str, content: &[u8]) -> Result<(), String> {
    let lower_name = filename.to_lowercase();

    // extensions interdites (double sécurité)
    let forbidden_ext = [".exe", ".bat", ".cmd", ".sh", ".ps1", ".dll", ".msi"];
    if forbidden_ext.iter().any(|ext| lower_name.ends_with(ext)) {
        return Err(format!("Extension dangereuse détectée ({lower_name})"));
    }

    // signature Windows PE (MZ)
    if content.starts_with(b"MZ") {
        return Err("Fichier exécutable détecté (signature MZ)".to_string());
    }

    // shebang scripts
    if content.starts_with(b"#!/bin/bash")
        || content.starts_with(b"#!/usr/bin/env bash")
        || content.starts_with(b"#!/bin/sh")
        || content.starts_with(b"#!/usr/bin/env sh")
    {
        return Err("Script shell détecté (shebang)".to_string());
    }

    Ok(())
}

async fn scan_with_clamav(data: &[u8]) -> Result<(), String> {
    let mut stream = UnixStream::connect("/var/run/clamav/clamd.ctl")
        .await
        .map_err(|e| format!("Impossible de se connecter à clamd (socket): {e}"))?;

    // INSTREAM
    stream
        .write_all(b"zINSTREAM\0")
        .await
        .map_err(|e| format!("Erreur envoi INSTREAM: {e}"))?;

    for chunk in data.chunks(8192) {
        let len = (chunk.len() as u32).to_be_bytes();
        stream.write_all(&len).await.map_err(|e| e.to_string())?;
        stream.write_all(chunk).await.map_err(|e| e.to_string())?;
    }

    // fin: len=0
    stream
        .write_all(&0u32.to_be_bytes())
        .await
        .map_err(|e| e.to_string())?;

    // lire réponse
    let mut buf = vec![0u8; 4096];
    let n = stream.read(&mut buf).await.map_err(|e| e.to_string())?;
    let resp = String::from_utf8_lossy(&buf[..n]).to_string();

    if resp.contains("OK") {
        Ok(())
    } else {
        Err(format!("ClamAV a rejeté le fichier: {resp}"))
    }
}

/// Convertit les erreurs axum/hyper en ApiError 413 si payload trop large
fn map_multipart_err_to_api_error(e: impl ToString) -> ApiError {
    let s = e.to_string().to_lowercase();
    if s.contains("length limit")
        || s.contains("body too large")
        || s.contains("request body too large")
        || s.contains("payload too large")
    {
        return ApiError::payload_too_large("fichier trop volumineux");
    }
    ApiError::bad_request("Erreur lecture multipart")
}

/// MAX_UPLOAD_BYTES (source unique)
fn max_upload_bytes() -> usize {
    std::env::var("MAX_UPLOAD_BYTES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(10 * 1024 * 1024) // 10 MiB par défaut
}

// ======================
// Structs
// ======================

#[derive(serde::Serialize)]
pub struct FileEntry {
    pub id: i64,
    pub filename: String,
    pub owner: String,
    pub size_bytes: i64,
    pub created_at: String,
}

#[derive(serde::Serialize)]
pub struct UploadResponse {
    pub status: String,
    pub message: String,
    pub filename: String,
    pub size_bytes: i64,
}

// ======================
// LIST FILES
// ======================

pub async fn list_files_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> ApiResult<Json<Vec<FileEntry>>> {
    let ip = client_ip(&headers);

    let owner_email = match get_user_from_headers(&headers) {
        Ok(email) => email,
        Err(msg) => {
            warn!(%ip, %msg, "list_unauthorized");
            return Err(ApiError::unauthorized());
        }
    };

    info!(%ip, owner=%owner_email, "list_start");

    let rows = sqlx::query(
        r#"
        SELECT id, filename, owner, size_bytes, created_at
        FROM files
        WHERE owner = ?1
        ORDER BY created_at DESC
        "#,
    )
    .bind(&owner_email)
    .fetch_all(&state.db)
    .await
    .map_err(|e| {
        error!(%ip, owner=%owner_email, error=%e, "list_db_error");
        ApiError::internal()
    })?;

    let entries: Vec<FileEntry> = rows
        .into_iter()
        .map(|row| FileEntry {
            id: row.try_get("id").unwrap_or_default(),
            filename: row.try_get("filename").unwrap_or_default(),
            owner: row.try_get("owner").unwrap_or_default(),
            size_bytes: row.try_get("size_bytes").unwrap_or_default(),
            created_at: row.try_get("created_at").unwrap_or_default(),
        })
        .collect();

    info!(%ip, owner=%owner_email, count=entries.len(), "list_ok");
    Ok(Json(entries))
}

// ======================
// UPLOAD
// ======================

pub async fn upload_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> ApiResult<Json<UploadResponse>> {
    let ip = client_ip(&headers);

    // Rate limit IP upload (30/min)
    rate_limit_or_err(&headers, "upload", 30, Duration::from_secs(60))?;

    // Source unique max upload
    let max_upload_u64 = max_upload_bytes() as u64;

    // Early block via Content-Length si présent
    if let Some(cl) = headers.get(CONTENT_LENGTH).and_then(|v| v.to_str().ok()) {
        if let Ok(size) = cl.parse::<u64>() {
            if size > max_upload_u64 {
                warn!(%ip, size, max_upload=max_upload_u64, "upload_blocked_content_length");
                return Err(ApiError::payload_too_large("fichier trop volumineux"));
            }
        }
    }

    let owner_email = match get_user_from_headers(&headers) {
        Ok(email) => email,
        Err(msg) => {
            warn!(%ip, %msg, "upload_unauthorized");
            return Err(ApiError::unauthorized());
        }
    };

    info!(%ip, owner=%owner_email, "upload_start");

    // Lire le champ multipart "file"
    let mut filename_opt: Option<String> = None;
    let mut bytes_opt: Option<Vec<u8>> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        warn!(%ip, owner=%owner_email, error=%e, "upload_multipart_read_error");
        map_multipart_err_to_api_error(e)
    })? {
        if field.name() == Some("file") {
            let fname = field.file_name().unwrap_or("upload.bin").to_string();

            let data = field.bytes().await.map_err(|e| {
                warn!(%ip, owner=%owner_email, file=%fname, error=%e, "upload_file_read_error");
                map_multipart_err_to_api_error(e)
            })?;

            filename_opt = Some(fname);
            bytes_opt = Some(data.to_vec());
            break;
        }
    }

    let filename = filename_opt
        .ok_or_else(|| ApiError::bad_request("Champ 'file' manquant dans le formulaire"))?;
    let bytes = bytes_opt.ok_or_else(|| ApiError::bad_request("Aucune donnée pour le fichier"))?;

    info!(%ip, owner=%owner_email, file=%filename, size=bytes.len(), "upload_received");

    // Fallback size check -> 413 (si pas de Content-Length ou si multipart/stack n'a pas bloqué)
    let max_upload = max_upload_bytes();
    if bytes.len() > max_upload {
        warn!(%ip, owner=%owner_email, file=%filename, size=bytes.len(), max=max_upload, "upload_too_large_env");
        return Err(ApiError::payload_too_large(format!(
            "fichier trop gros (max {} bytes)",
            max_upload
        )));
    }

    // Extensions interdites (rapide)
    if is_forbidden_extension(&filename) {
        warn!(%ip, owner=%owner_email, file=%filename, "upload_blocked_forbidden_extension");
        return Err(ApiError::file_refused());
    }

    // Scan basique (rapide)
    if let Err(reason) = basic_malware_scan(&filename, &bytes) {
        warn!(%ip, owner=%owner_email, file=%filename, %reason, "upload_blocked_basic_scan");
        return Err(ApiError::virus_detected());
    }

    // Scan ClamAV avant enregistrement
    if let Err(reason) = scan_with_clamav(&bytes).await {
        warn!(%ip, owner=%owner_email, file=%filename, %reason, "upload_blocked_clamav");
        return Err(ApiError::virus_detected());
    }

    let size_bytes = bytes.len() as i64;

    // Quota par utilisateur (AVANT write disque)
    let max_user_storage: i64 = std::env::var("MAX_STORAGE_PER_USER_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1024 * 1024 * 1024); // 1 GiB défaut

    let (used_bytes,): (i64,) =
        sqlx::query_as(r#"SELECT COALESCE(SUM(size_bytes), 0) FROM files WHERE owner = ?1"#)
            .bind(&owner_email)
            .fetch_one(&state.db)
            .await
            .map_err(|e| {
                error!(%ip, owner=%owner_email, error=%e, "quota_db_sum_failed");
                ApiError::internal()
            })?;

    if used_bytes + size_bytes > max_user_storage {
        warn!(%ip, owner=%owner_email, used_bytes, upload=size_bytes, max=max_user_storage, "quota_exceeded");
        return Err(ApiError::quota_exceeded("quota de stockage dépassé"));
    }

    // Dossier upload
    let upload_dir = uploads_dir();
    tokio::fs::create_dir_all(&upload_dir).await.map_err(|e| {
        error!(%ip, owner=%owner_email, error=%e, "upload_create_dir_failed");
        ApiError::internal()
    })?;

    // éviter path traversal
    let safe_name = Path::new(&filename)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("upload.bin")
        .to_string();

    let file_path = upload_dir.join(&safe_name);

    // Check espace disque (AVANT write)
    // On veut: après écriture, il reste au moins MIN_FREE_BYTES
    let min_free: u64 = std::env::var("MIN_FREE_BYTES")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(2_u64 * 1024 * 1024 * 1024); // 2 GiB default

    let vfs = statvfs(&upload_dir).map_err(|e| {
        error!(%ip, owner=%owner_email, error=%e, "statvfs_failed");
        ApiError::internal()
    })?;

    let free_bytes = (vfs.blocks_available() as u64) * (vfs.block_size() as u64);
    let file_size = bytes.len() as u64;

    if free_bytes < file_size + min_free {
        warn!(%ip, owner=%owner_email, free_bytes, file_size, min_free, "insufficient_storage");
        return Err(ApiError::insufficient_storage(format!(
            "espace disque insuffisant (free {} / need {} bytes)",
            free_bytes,
            file_size + min_free
        )));
    }

    // Write disque
    tokio::fs::write(&file_path, &bytes).await.map_err(|e| {
        error!(%ip, owner=%owner_email, file=%safe_name, error=%e, path=%file_path.display(), "upload_write_failed");
        ApiError::internal()
    })?;

    // Insert DB (après write OK) - cleanup si insert fail
    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO files (filename, owner, size_bytes, created_at)
        VALUES (?1, ?2, ?3, datetime('now'))
        "#,
    )
    .bind(&safe_name)
    .bind(&owner_email)
    .bind(size_bytes)
    .execute(&state.db)
    .await
    {
        error!(%ip, owner=%owner_email, file=%safe_name, error=%e, "upload_db_insert_failed");

        if let Err(e2) = tokio::fs::remove_file(&file_path).await {
            warn!(%ip, owner=%owner_email, file=%safe_name, error=%e2, "upload_cleanup_failed");
        }

        return Err(ApiError::internal());
    }

    info!(%ip, owner=%owner_email, file=%safe_name, size_bytes=size_bytes, "upload_ok");

    Ok(Json(UploadResponse {
        status: "ok".to_string(),
        message: "Fichier uploadé".to_string(),
        filename: safe_name,
        size_bytes,
    }))
}

// ======================
// DOWNLOAD
// ======================

pub async fn download_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(id): AxumPath<i64>,
) -> ApiResult<Response> {
    let ip = client_ip(&headers);

    let owner_email = match get_user_from_headers(&headers) {
        Ok(email) => email,
        Err(msg) => {
            warn!(%ip, %msg, "download_unauthorized");
            return Err(ApiError::unauthorized());
        }
    };

    let row = sqlx::query(r#"SELECT filename, owner FROM files WHERE id = ?1"#)
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            warn!(%ip, owner=%owner_email, file_id=id, error=%e, "download_not_found_db");
            ApiError::not_found("Fichier introuvable")
        })?;

    let owner: String = row.try_get("owner").unwrap_or_default();
    let filename: String = row.try_get("filename").unwrap_or_default();

    // hide existence si pas owner
    if owner != owner_email {
        warn!(%ip, user=%owner_email, file_id=id, "download_hidden_not_owner");
        return Err(ApiError::not_found("Fichier introuvable"));
    }

    let safe_name = Path::new(&filename)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("upload.bin")
        .to_string();

    let path = uploads_dir().join(&safe_name);

    let bytes = tokio::fs::read(&path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            warn!(%ip, owner=%owner_email, file_id=id, path=%path.display(), "download_not_found_disk");
            ApiError::not_found("Fichier introuvable")
        } else {
            error!(%ip, owner=%owner_email, file_id=id, error=%e, path=%path.display(), "download_read_error");
            ApiError::internal()
        }
    })?;

    let resp = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(Body::from(bytes))
        .map_err(|_| ApiError::internal())?;

    Ok(resp)
}

// ======================
// DELETE
// ======================

pub async fn delete_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(id): AxumPath<i64>,
) -> ApiResult<Json<serde_json::Value>> {
    let ip = client_ip(&headers);

    let owner_email = match get_user_from_headers(&headers) {
        Ok(email) => email,
        Err(msg) => {
            warn!(%ip, %msg, "delete_unauthorized");
            return Err(ApiError::unauthorized());
        }
    };

    let row = sqlx::query(r#"SELECT filename, owner FROM files WHERE id = ?1"#)
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            warn!(%ip, owner=%owner_email, file_id=id, error=%e, "delete_not_found_db");
            ApiError::not_found("Fichier introuvable")
        })?;

    let owner: String = row.try_get("owner").unwrap_or_default();
    let filename: String = row.try_get("filename").unwrap_or_default();

    // hide existence si pas owner
    if owner != owner_email {
        warn!(%ip, owner=%owner_email, file_id=id, "delete_hidden_not_owner");
        return Err(ApiError::not_found("Fichier introuvable"));
    }

    let safe_name = Path::new(&filename)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("upload.bin")
        .to_string();

    let path = uploads_dir().join(&safe_name);

    if let Err(e) = tokio::fs::remove_file(&path).await {
        if e.kind() != std::io::ErrorKind::NotFound {
            error!(%ip, owner=%owner_email, file_id=id, error=%e, path=%path.display(), "delete_disk_error");
            return Err(ApiError::internal());
        }
    }

    sqlx::query(r#"DELETE FROM files WHERE id = ?1"#)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            error!(%ip, owner=%owner_email, file_id=id, error=%e, "delete_db_error");
            ApiError::internal()
        })?;

    info!(%ip, owner=%owner_email, file_id=id, filename=%filename, "delete_ok");

    Ok(Json(serde_json::json!({
        "status": "ok",
        "message": format!("Fichier {} supprimé", id),
        "filename": filename,
        "owner": owner_email,
    })))
}

// ======================
// Tests
// ======================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_extensions_work() {
        assert!(is_forbidden_extension("virus.exe"));
        assert!(is_forbidden_extension("payload.DLL"));
        assert!(is_forbidden_extension("script.sh"));
        assert!(!is_forbidden_extension("photo.png"));
        assert!(!is_forbidden_extension("note.txt"));
    }

    #[test]
    fn basic_scan_blocks_mz_exe_signature() {
        let data = b"MZ....fake";
        let r = basic_malware_scan("ok.txt", data);
        assert!(r.is_err());
    }

    #[test]
    fn basic_scan_blocks_shell_shebang() {
        let data = b"#!/bin/bash\necho hi";
        let r = basic_malware_scan("ok.txt", data);
        assert!(r.is_err());
    }

    #[test]
    fn basic_scan_allows_normal_text() {
        let data = b"hello world";
        let r = basic_malware_scan("readme.txt", data);
        assert!(r.is_ok());
    }
}
