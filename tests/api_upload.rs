use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use sqlx::SqlitePool;
use tower::ServiceExt; // oneshot

use jsecure_cloud::api::{api_router, AppState};

use tempfile::tempdir;

async fn setup_test_app() -> axum::Router {
    let tmp = tempdir().unwrap();

    std::env::set_var("UPLOAD_DIR", tmp.path().join("uploads"));
    std::env::set_var("UPLOAD_TMP_DIR", tmp.path().join("tmp"));
    std::env::set_var("CLAMD_DISABLED", "1");
    std::env::set_var("JWT_SECRET", "TEST_SECRET_123");

    let db = SqlitePool::connect("sqlite::memory:").await.unwrap();

    sqlx::query(r#"
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
    "#)
    .execute(&db)
    .await
    .unwrap();

    let state = AppState { db };
    api_router(state)
}
/// Helper: register + login, retourne un token JWT
async fn register_and_login(app: &axum::Router) -> String {
    std::env::set_var("JWT_SECRET", "TEST_SECRET_UPLOAD");

    // register
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"email":"u@u.com","password":"pass1234"}"#,
        ))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // login
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(
            r#"{"email":"u@u.com","password":"pass1234"}"#,
        ))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let s = String::from_utf8(body.to_vec()).unwrap();

    let token = s
        .split("\"token\":\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();

    token.to_string()
}

#[tokio::test]
async fn upload_requires_auth() {
    let app = setup_test_app().await;

    let body = "--x\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\
                Content-Type: text/plain\r\n\r\nhello\r\n--x--";

    let req = Request::builder()
        .method("POST")
        .uri("/api/files/upload")
        .header("content-type", "multipart/form-data; boundary=x")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn upload_too_large_returns_413() {
    let app = setup_test_app().await;
    let token = register_and_login(&app).await;

    // limite volontairement très basse pour le test
    std::env::set_var("MAX_UPLOAD_BYTES", "10");

    let big_payload = "A".repeat(100);

    let body = format!(
        "--x\r\n\
         Content-Disposition: form-data; name=\"file\"; filename=\"big.txt\"\r\n\
         Content-Type: text/plain\r\n\r\n\
         {}\r\n\
         --x--",
        big_payload
    );

    let req = Request::builder()
        .method("POST")
        .uri("/api/files/upload")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "multipart/form-data; boundary=x")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn upload_small_file_ok() {
    let app = setup_test_app().await;
    let token = register_and_login(&app).await;

    std::env::set_var("MAX_UPLOAD_BYTES", "1024");

    let body = "--x\r\n\
                Content-Disposition: form-data; name=\"file\"; filename=\"ok.txt\"\r\n\
                Content-Type: text/plain\r\n\r\nhello world\r\n--x--";

    let req = Request::builder()
        .method("POST")
        .uri("/api/files/upload")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "multipart/form-data; boundary=x")
        .body(Body::from(body))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}
