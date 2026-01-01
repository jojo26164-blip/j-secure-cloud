use axum::{
    body::Body,
    http::{header, Request, StatusCode},
};
use http_body_util::BodyExt;
use jsecure_cloud::api::{api_router, AppState};
use sqlx::SqlitePool;
use tempfile::tempdir;
use tower::ServiceExt; // oneshot

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

/// extrait "jwt=...." depuis Set-Cookie
fn extract_jwt_cookie(set_cookie_value: &str) -> String {
    // set-cookie: jwt=XXX; HttpOnly; ...
    // on veut "jwt=XXX"
    let first = set_cookie_value.split(';').next().unwrap_or("").trim();
    first.to_string()
}

/// crée un header Cookie: jwt=...
fn cookie_header(jwt_cookie: &str) -> (header::HeaderName, header::HeaderValue) {
    (
        header::COOKIE,
        header::HeaderValue::from_str(jwt_cookie).unwrap(),
    )
}

/// Register + login et retourne "jwt=...." pour l'envoyer ensuite en Cookie:
async fn register_and_login_cookie(app: &axum::Router, email: &str) -> String {
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/register")
        .header(header::CONTENT_TYPE, "application/json")
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
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(format!(
            r#"{{"email":"{}","password":"pass1234"}}"#,
            email
        )))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // récupère le Set-Cookie
    let set_cookie = resp
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .next()
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    assert!(
        set_cookie.contains("jwt="),
        "login doit renvoyer un Set-Cookie jwt=..., got: {set_cookie}"
    );

    extract_jwt_cookie(set_cookie)
}

async fn upload_one(app: &axum::Router, jwt_cookie: &str, filename: &str, content: &str) {
    // multipart minimal
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
        .header(header::CONTENT_TYPE, "multipart/form-data; boundary=x")
        .header(cookie_header(jwt_cookie).0, cookie_header(jwt_cookie).1)
        .body(Body::from(body))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

async fn list_first_id(app: &axum::Router, jwt_cookie: &str) -> i64 {
    let req = Request::builder()
        .method("GET")
        .uri("/api/files")
        .header(cookie_header(jwt_cookie).0, cookie_header(jwt_cookie).1)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let s = String::from_utf8(body.to_vec()).unwrap();

    // parse simple
    let id_str = s.split("\"id\":").nth(1).unwrap();
    let id_num = id_str
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect::<String>();

    id_num.parse::<i64>().unwrap()
}

async fn download_status(app: &axum::Router, jwt_cookie: &str, id: i64) -> StatusCode {
    let req = Request::builder()
        .method("GET")
        .uri(format!("/api/files/{}/download", id))
        .header(cookie_header(jwt_cookie).0, cookie_header(jwt_cookie).1)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    resp.status()
}

#[tokio::test]
async fn delete_requires_auth() {
    let app = setup_test_app().await;

    let req = Request::builder()
        .method("DELETE")
        .uri("/api/files/1")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn delete_ok_then_download_404() {
    let app = setup_test_app().await;

    let cookie = register_and_login_cookie(&app, "u@u.com").await;
    upload_one(&app, &cookie, "ok.txt", "hello world").await;

    let id = list_first_id(&app, &cookie).await;

    // delete
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/files/{}", id))
        .header(cookie_header(&cookie).0, cookie_header(&cookie).1)
        .body(Body::empty())
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // download should now be 404
    let st = download_status(&app, &cookie, id).await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_not_owner_is_404() {
    let app = setup_test_app().await;

    let cookie_a = register_and_login_cookie(&app, "a@a.com").await;
    let cookie_b = register_and_login_cookie(&app, "b@b.com").await;

    upload_one(&app, &cookie_a, "secret.txt", "top secret").await;
    let id = list_first_id(&app, &cookie_a).await;

    // B tente de delete le fichier de A => NOT_FOUND (anti-enum)
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/api/files/{}", id))
        .header(cookie_header(&cookie_b).0, cookie_header(&cookie_b).1)
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
