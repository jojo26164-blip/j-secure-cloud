use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use sqlx::SqlitePool;
use tower::ServiceExt; // oneshot
use tempfile::tempdir;

use jsecure_cloud::api::{api_router, AppState};

async fn setup_test_app() -> axum::Router {
    let tmp = tempdir().unwrap();

    // Dossiers temporaires pour uploads / tmp
    std::env::set_var("UPLOAD_DIR", tmp.path().join("uploads"));
    std::env::set_var("UPLOAD_TMP_DIR", tmp.path().join("tmp"));

    // Désactive ClamAV pour les tests (si ton code le supporte)
    std::env::set_var("CLAMD_DISABLED", "1");

    // JWT secret stable pour tests
    std::env::set_var("JWT_SECRET", "TEST_SECRET_123");

    // Upload max (petit pour tests)
    std::env::set_var("MAX_UPLOAD_BYTES", "1024");

    let db = SqlitePool::connect("sqlite::memory:").await.unwrap();

    // Schéma minimal pour auth + files (comme tes autres tests)
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

/// Récupère le JWT depuis `Set-Cookie: jwt=...; ...`
fn extract_jwt_from_set_cookie(headers: &axum::http::HeaderMap) -> String {
    let all = headers.get_all(axum::http::header::SET_COOKIE);

    for v in all.iter() {
        if let Ok(s) = v.to_str() {
            if let Some(rest) = s.strip_prefix("jwt=") {
                let jwt = rest.split(';').next().unwrap_or("").trim();
                if !jwt.is_empty() {
                    return jwt.to_string();
                }
            }
        }
    }

    panic!("No jwt cookie found in Set-Cookie");
}

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

    extract_jwt_from_set_cookie(resp.headers())
}

async fn upload_one(app: &axum::Router, jwt: &str, filename: &str, content: &str) {
    // Multipart minimal (boundary "x")
    let body = format!(
        "--x\r\n\
Content-Disposition: form-data; name=\"file\"; filename=\"{}\"\r\n\
Content-Type: text/plain\r\n\r\n\
{}\r\n\
--x--\r\n",
        filename, content
    );

    let req = Request::builder()
        .method("POST")
        .uri("/api/files/upload")
        .header("cookie", format!("jwt={}", jwt))
        .header("content-type", "multipart/form-data; boundary=x")
        .body(Body::from(body))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

async fn list_first_id(app: &axum::Router, jwt: &str) -> i64 {
    let req = Request::builder()
        .method("GET")
        .uri("/api/files")
        .header("cookie", format!("jwt={}", jwt))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let s = String::from_utf8(body.to_vec()).unwrap();

    // On parse "id":<digits> du premier élément
    let id_str = s
        .split("\"id\":")
        .nth(1)
        .expect("No id field found in list response");

    let id_num = id_str
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>();

    id_num.parse::<i64>().unwrap()
}

async fn download(app: &axum::Router, jwt: &str, id: i64) -> (StatusCode, Vec<u8>) {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/files/{}/download", id))
        .header("cookie", format!("jwt={}", jwt))
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let body = resp.into_body().collect().await.unwrap().to_bytes().to_vec();
    (status, body)
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

    let jwt = register_and_login_cookie(&app, "u@u.com").await;
    upload_one(&app, &jwt, "ok.txt", "hello world").await;
    let id = list_first_id(&app, &jwt).await;

    let (st, bytes) = download(&app, &jwt, id).await;
    assert_eq!(st, StatusCode::OK);

    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("hello world"));
}

#[tokio::test]
async fn download_not_owner_is_404() {
    let app = setup_test_app().await;

    let jwt_a = register_and_login_cookie(&app, "a@a.com").await;
    let jwt_b = register_and_login_cookie(&app, "b@b.com").await;

    upload_one(&app, &jwt_a, "secret.txt", "top secret").await;
    let id = list_first_id(&app, &jwt_a).await;

    let (st, _bytes) = download(&app, &jwt_b, id).await;
assert_eq!(st, StatusCode::FORBIDDEN);
}
