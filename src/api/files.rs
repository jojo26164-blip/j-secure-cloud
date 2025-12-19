use axum::{
    body::Body,
    extract::{Multipart, Path as AxumPath, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio_util::io::ReaderStream;

use crate::api::auth::get_user_from_headers;
use crate::api::error::{ApiError, ApiResult};
use crate::api::AppState;

use sqlx::Row;
use std::path::{Path, PathBuf};
use tracing::{error, info, warn};

async fn scan_with_clamav(data: &[u8]) -> Result<(), String> {
    let mut stream = UnixStream::connect("/var/run/clamav/clamd.ctl")
        .await
        .map_err(|e| format!("Impossible de se connecter à clamd (socket): {e}"))?;

    // INSTREAM\n
    stream
        .write_all(b"zINSTREAM\0")
        .await
        .map_err(|e| format!("Erreur envoi INSTREAM: {e}"))?;

    // envoi par chunks: [len(4 bytes BE)] + data
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

    // réponses typiques: "stream: OK" ou "stream: Eicar-Test-Signature FOUND"
    if resp.contains("OK") {
        Ok(())
    } else {
        Err(format!("ClamAV a rejeté le fichier: {resp}"))
    }
}

fn is_forbidden_extension(filename: &str) -> bool {
    // on met tout en minuscule pour être sûr
    let lower = filename.to_lowercase();

    // extensions qu’on interdit pour l’instant
    let forbidden = [".exe", ".dll", ".bat", ".cmd", ".sh", ".msi"];

    forbidden.iter().any(|ext| lower.ends_with(ext))
}

// ======================================
//  STRUCTS
// ======================================

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

// ======================
//  LISTE DES FICHIERS
// ======================

pub async fn list_files_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<FileEntry>>, (StatusCode, String)> {
    let ip = client_ip(&headers);

    // email depuis token
    let owner_email = match get_user_from_headers(&headers) {
        Ok(email) => email,
        Err(msg) => {
            warn!(%ip, %msg, "list_unauthorized");
            return Err((StatusCode::UNAUTHORIZED, msg));
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
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Erreur DB (select files): {e}"),
        )
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

fn basic_malware_scan(filename: &str, content: &[u8]) -> Result<(), String> {
    let lower_name = filename.to_lowercase();

    // 1) extensions interdites (double sécurité)
    let forbidden_ext = [".exe", ".bat", ".cmd", ".sh", ".ps1", ".dll", ".msi"];
    if forbidden_ext.iter().any(|ext| lower_name.ends_with(ext)) {
        return Err(format!("Extension dangereuse détectée ({lower_name})"));
    }

    // 2) signature Windows PE (MZ)
    if content.starts_with(b"MZ") {
        return Err("Fichier exécutable détecté (signature MZ)".to_string());
    }

    // 3) shebang scripts
    if content.starts_with(b"#!/bin/bash")
        || content.starts_with(b"#!/usr/bin/env bash")
        || content.starts_with(b"#!/bin/sh")
        || content.starts_with(b"#!/usr/bin/env sh")
    {
        return Err("Script shell détecté (shebang)".to_string());
    }

    Ok(())
}

// ======================
//  UPLOAD FICHIER
// ======================

pub async fn upload_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    mut multipart: Multipart,
) -> ApiResult<impl IntoResponse> {
    let ip = client_ip(&headers);

    // email depuis token
    let owner_email = match get_user_from_headers(&headers) {
        Ok(email) => email,
        Err(msg) => {
            warn!(%ip, %msg, "upload_unauthorized");
            return Err(ApiError::unauthorized());
        }
    };

    info!(%ip, owner=%owner_email, "upload_start");

    // lire le champ multipart "file"
    let mut filename_opt: Option<String> = None;
    let mut bytes_opt: Option<Vec<u8>> = None;

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        warn!(%ip, owner=%owner_email, error=%e, "upload_multipart_read_error");
        ApiError::bad_request("Erreur lecture multipart")
    })? {
        if field.name() == Some("file") {
            let fname = field.file_name().unwrap_or("upload.bin").to_string();
            let data = field.bytes().await.map_err(|e| {
                warn!(%ip, owner=%owner_email, file=%fname, error=%e, "upload_file_read_error");
                ApiError::bad_request("Erreur lecture fichier")
            })?;

            filename_opt = Some(fname);
            bytes_opt = Some(data.to_vec());
            break;
        }
    }

    let filename = filename_opt.ok_or(ApiError::bad_request(
        "Champ 'file' manquant dans le formulaire",
    ))?;
    let bytes = bytes_opt.ok_or(ApiError::bad_request("Aucune donnée pour le fichier"))?;

    info!(%ip, owner=%owner_email, file=%filename, size=bytes.len(), "upload_received");

    // ✅ Scan ClamAV AVANT enregistrement
    if let Err(reason) = scan_with_clamav(&bytes).await {
        return Err(ApiError::bad_request(format!("CLAMAV_FAIL: {reason}")));
    }

    // 🔒 extensions interdites
    if is_forbidden_extension(&filename) {
        warn!(%ip, owner=%owner_email, file=%filename, "upload_blocked_forbidden_extension");
        return Err(ApiError::bad_request("type de fichier interdit"));
    }

    // 🔍 scan basique
    if let Err(reason) = basic_malware_scan(&filename, &bytes) {
        warn!(%ip, owner=%owner_email, file=%filename, %reason, "upload_blocked_basic_scan");
        return Err(ApiError::bad_request("virus détecté"));
    }

    let size_bytes = bytes.len() as i64;

    // dossier upload
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
    tokio::fs::write(&file_path, &bytes).await.map_err(|e| {
        ApiError::bad_request(format!("DISK_WRITE_FAIL: {e} path={}", file_path.display()))
    })?;

    // insert DB
    sqlx::query(
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
    .map_err(|e| ApiError::bad_request(format!("DB_INSERT_FAIL: {e}")))?;

    info!(%ip, owner=%owner_email, file=%safe_name, size_bytes=size_bytes, "upload_ok");

    Ok(Json(UploadResponse {
        status: "ok".to_string(),
        message: "Fichier uploadé".to_string(),
        filename: safe_name,
        size_bytes,
    }))
}

// ======================
//  DOWNLOAD FICHIER
// ======================

pub async fn download_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(id): AxumPath<i64>,
) -> Result<Response, (StatusCode, String)> {
    let owner_email = match get_user_from_headers(&headers) {
        Ok(email) => email,
        Err(msg) => return Err((StatusCode::UNAUTHORIZED, msg)),
    };
    // 2) récupérer le fichier dans la DB
    let row = sqlx::query(r#"SELECT filename, owner FROM files WHERE id = ?1"#)
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::NOT_FOUND,
                format!("Fichier id {} introuvable: {e}", id),
            )
        })?;

    let owner: String = row.try_get("owner").unwrap_or_default();
    let filename: String = row.try_get("filename").unwrap_or_default();

    if owner != owner_email {
        warn!(
            user = %owner_email,
            file_id = id,
            "download_forbidden"
        );
        return Err((
            StatusCode::FORBIDDEN,
            "Accès interdit : ce fichier ne vous appartient pas".to_string(),
        ));
    }

    // 3) ouvrir le fichier sur disque
    let safe_name = Path::new(&filename)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("upload.bin")
        .to_string();

    let path = uploads_dir().join(&safe_name);

    let file = tokio::fs::File::open(&path).await.map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            (
                StatusCode::NOT_FOUND,
                format!(
                    "Fichier absent sur disque (id={id}) path={}",
                    path.display()
                ),
            )
        } else {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Erreur ouverture fichier: {e} path={}", path.display()),
            )
        }
    })?;

    let stream = ReaderStream::new(file);
    let body = Body::from_stream(stream); // ✅

    let resp = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/octet-stream")
        .header(
            "Content-Disposition",
            format!("attachment; filename=\"{}\"", filename),
        )
        .body(body)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Erreur création réponse: {e}"),
            )
        })?;
    info!(owner = %owner_email, file_id = id, filename = %filename, "download_ok");
    Ok(resp)
}

// ======================
//  DELETE FICHIER
// ======================

pub async fn delete_handler(
    headers: HeaderMap,
    State(state): State<AppState>,
    AxumPath(id): AxumPath<i64>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let owner_email = match get_user_from_headers(&headers) {
        Ok(email) => email,
        Err(msg) => return Err((StatusCode::UNAUTHORIZED, msg)),
    };

    // 2) Récupérer filename + owner dans la DB
    let row = sqlx::query(r#"SELECT filename, owner FROM files WHERE id = ?1"#)
        .bind(id)
        .fetch_one(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::NOT_FOUND,
                format!("Fichier id {} introuvable: {e}", id),
            )
        })?;

    let owner: String = row.try_get("owner").unwrap_or_default();
    let filename: String = row.try_get("filename").unwrap_or_default();

    // 3) Vérifier que le fichier appartient bien à l’utilisateur connecté
    if owner != owner_email {
        warn!(owner = %owner_email, file_owner = %owner, file_id = id, "delete_forbidden");
        return Err((
            StatusCode::FORBIDDEN,
            "Accès interdit : ce fichier ne vous appartient pas".to_string(),
        ));
    }

    // 4) Supprimer le fichier sur disque (si présent)
    let safe_name = Path::new(&filename)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("upload.bin")
        .to_string();

    let path = uploads_dir().join(&safe_name);
    if let Err(e) = tokio::fs::remove_file(&path).await {
        // On ignore si le fichier n'existe plus, sinon on renvoie une erreur
        if e.kind() != std::io::ErrorKind::NotFound {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Erreur suppression fichier sur disque: {e}"),
            ));
        }
    }

    // 5) Supprimer l’entrée en base
    sqlx::query(r#"DELETE FROM files WHERE id = ?1"#)
        .bind(id)
        .execute(&state.db)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Erreur DB (delete): {e}"),
            )
        })?;

    // 6) Réponse OK
    info!(owner = %owner_email, file_id = id, filename = %filename, "delete_ok");
    Ok(Json(serde_json::json!({
        "status": "ok",
        "message": format!("Fichier {} supprimé", id),
        "filename": filename,
        "owner": owner_email,
    })))
}
