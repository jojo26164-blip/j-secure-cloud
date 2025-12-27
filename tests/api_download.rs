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
    std::env::set_var("MAX_UPLOAD_BYTES", "1024");

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

// Helper: register + login => token
async fn register_and_login(app: &axum::Router, email: &str) -> String {
    std::env::set_var("JWT_SECRET", "TEST_SECRET_UPLOAD");

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

// Helper: upload small file
async fn upload_one(app: &axum::Router, token: &str, filename: &str, content: &str) {
    let body = format!(
        "--x\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n\
Content-Type: text/plain\r\n\r\n\
{}\r\n\
--x--",
        filename, content
    );

    let req = Request::builder()
        .method("POST")
        .uri("/api/files/upload")
        .header("authorization", format!("Bearer {}", token))
        .header("content-type", "multipart/form-data; boundary=x")
        .body(Body::from(body))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

// Helper: list files, return first id
async fn list_first_id(app: &axum::Router, token: &str) -> i64 {
    let req = Request::builder()
        .method("GET")
        .uri("/api/files")
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let s = String::from_utf8(body.to_vec()).unwrap();

    // JSON array: [{"id":123,...}]
    let id_str = s.split("\"id\":").nth(1).unwrap();
    let id_num = id_str
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>();
    id_num.parse::<i64>().unwrap()
}

#[tokio::test]
async fn download_requires_auth() {
    let app = setup_test_app().await;
    let req = Request::builder()
        .method("GET")
        .uri("/api/files/1/download")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn download_ok_returns_bytes() {
    let app = setup_test_app().await;
    let token = register_and_login(&app, "u@u.com").await;

    upload_one(&app, &token, "ok.txt", "hello world").await;
    let id = list_first_id(&app, &token).await;

    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/files/{}/download", id))
        .header("authorization", format!("Bearer {}", token))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    assert!(!bytes.is_empty());
    let s = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(s.contains("hello world"));
}

#[tokio::test]
async fn download_not_owner_is_404() {
    let app = setup_test_app().await;
    let token_a = register_and_login(&app, "a@a.com").await;
    let token_b = register_and_login(&app, "b@b.com").await;

    upload_one(&app, &token_a, "secret.txt", "top secret").await;
    let id = list_first_id(&app, &token_a).await;

    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/files/{}/download", id))
        .header("authorization", format!("Bearer {}", token_b))
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
