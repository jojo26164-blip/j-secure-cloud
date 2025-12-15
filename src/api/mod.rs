use axum::{
    routing::{delete, get, post},
    middleware,
    Router,
};

pub mod auth;
pub mod files;
pub mod error;
pub mod rate_limit;
pub mod health;

use crate::api::rate_limit::{RateLimiter, rate_limit_mw};

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::SqlitePool,
}

pub fn api_router() -> Router<AppState> {
    let limiter = RateLimiter::new();

    Router::new()
        .route("/health", get(health::health_handler))
        .route("/auth/login", post(auth::login_handler))
        .route("/auth/register", post(auth::register_handler))
        .route("/files", get(files::list_files_handler))
        .route("/files/upload", post(files::upload_handler))
        .route("/files/:id/download", get(files::download_handler))
        .route("/files/:id", delete(files::delete_handler))
        .layer(middleware::from_fn_with_state(limiter, rate_limit_mw))
}
