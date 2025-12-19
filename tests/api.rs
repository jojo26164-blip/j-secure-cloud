use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use http_body_util::BodyExt;
use sqlx::SqlitePool;
use tower::ServiceExt; // oneshot

use jsecure_cloud::api::{api_router, AppState};

async fn setup_test_app() -> axum::Router {
    // DB SQLite en mémoire pour tests
    let db = SqlitePool::connect("sqlite::memory:").await.unwrap();

    // Schéma minimal (adapte si ton projet a un migrate)
    sqlx::query(
        r#"
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
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

#[tokio::test]
async fn test_register_then_login() {
    std::env::set_var("JWT_SECRET", "TEST_SECRET_123");

    let app = setup_test_app().await;

    // 1) Register
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/register")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"email":"a@a.com","password":"pass1234"}"#))
        .unwrap();

    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 2) Login
    let req = Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"email":"a@a.com","password":"pass1234"}"#))
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
    assert!(body_str.contains("\"token\""));
}

#[tokio::test]
async fn test_list_files_requires_auth() {
    let app = setup_test_app().await;

    let req = Request::builder()
        .method("GET")
        .uri("/api/files")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();

    // Chez toi tu renvoies UNAUTHORIZED si pas Authorization
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
