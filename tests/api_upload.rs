use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sqlx::SqlitePool;
use tempfile::tempdir;
use tower::ServiceExt; // oneshot

use jsecure_cloud::api::{api_router, AppState};

async fn setup_test_app(max_upload_bytes: usize) -> axum::Router {
    let tmp = tempdir().unwrap();

    let upload_dir = tmp.path().join("uploads");
    let tmp_dir = tmp.path().join("tmp");
    std::fs::create_dir_all(&upload_dir).unwrap();
    std::fs::create_dir_all(&tmp_dir).unwrap();

    std::env::set_var("UPLOAD_DIR", upload_dir);
    std::env::set_var("TMP_DIR", tmp_dir);
    std::env::set_var("CLAMD_DISABLED", "1");
    std::env::set_var("JWT_SECRET", "TEST_SECRET_123");
    std::env::set_var("MAX_UPLOAD_BYTES", max_upload_bytes.to_string());

    let db = SqlitePool::connect("sqlite::memory:").await.unwrap();
    sqlx::query(
        r#"
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_blocked INTEGER DEFAULT 0,
            quota_bytes INTEGER
        );
        CREATE TABLE files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            owner TEXT NOT NULL,
            size_bytes INTEGER NOT NULL,
            created_at TEXT NOT NULL
        );
        "#,
    )
    .execute(&db)
    .await
    .unwrap();

    let state = AppState { db };
    api_router(state)
}

/// Renvoie un header Cookie prêt à l'emploi: "jwt=...."
async fn register_and_login_cookie(app: &axum::Router, email: &str) -> String {
    // register
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"email":"{}","password":"pass1234"}}"#,
            email
        )))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // login
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(format!(
            r#"{{"email":"{}","password":"pass1234"}}"#,
            email
        )))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // extract Set-Cookie
    let set_cookie = resp
        .headers()
        .get(axum::http::header::SET_COOKIE)
        .and_then(|v| v.to_str().ok())
        .expect("missing Set-Cookie from login");

    // ex: "jwt=XYZ; HttpOnly; SameSite=Lax; Path=/; Max-Age=..."
    let jwt_pair = set_cookie
        .split(';')
        .next()
        .expect("bad Set-Cookie format");

    jwt_pair.to_string()
}

async fn upload_multipart(
    app: &axum::Router,
    cookie_jwt: Option<&str>,
    filename: &str,
    bytes: &[u8],
) -> StatusCode {
    let boundary = "x";

    let mut body = Vec::new();
    body.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
    body.extend_from_slice(
        format!(
            "Content-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n",
            filename
        )
        .as_bytes(),
    );
    body.extend_from_slice(b"Content-Type: application/octet-stream\r\n\r\n");
    body.extend_from_slice(bytes);
    body.extend_from_slice(b"\r\n");
    body.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());

    let mut req = Request::builder()
        .method("POST")
        .uri("/api/files/upload")
        .header("content-type", format!("multipart/form-data; boundary={}", boundary));

    if let Some(c) = cookie_jwt {
        req = req.header("cookie", c);
    }

    let req = req.body(Body::from(body)).unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    resp.status()
}

#[tokio::test]
async fn upload_requires_auth() {
    let app = setup_test_app(1024).await;

    let st = upload_multipart(&app, None, "a.txt", b"hello").await;
    assert_eq!(st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn upload_small_file_ok() {
    let app = setup_test_app(1024).await;

    let cookie = register_and_login_cookie(&app, "u@u.com").await;
    let st = upload_multipart(&app, Some(&cookie), "ok.txt", b"hello world").await;

    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn upload_too_large_returns_413() {
    let app = setup_test_app(1024).await;

    let cookie = register_and_login_cookie(&app, "u2@u.com").await;
    let big = vec![b'a'; 2048];

    let st = upload_multipart(&app, Some(&cookie), "big.bin", &big).await;
    assert_eq!(st, StatusCode::PAYLOAD_TOO_LARGE);
}
