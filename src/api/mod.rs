use axum::{
    middleware,
    routing::{delete, get, post},
    Router,
};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use tower_http::cors::{Any, CorsLayer};

pub mod auth;
pub mod error;
pub mod files;
pub mod health;
pub mod rate_limit;

use crate::api::rate_limit::rate_limit_mw;
use crate::api::rate_limit::RateLimiter;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::SqlitePool,
    pub limiter: RateLimiter, // ✅ ajouté
}

pub fn api_router(state: AppState) -> Router {
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers([AUTHORIZATION, CONTENT_TYPE]);

    let api = Router::new()
        .route("/health", get(health::health_handler))
        .route("/auth/login", post(auth::login_handler))
        .route("/auth/register", post(auth::register_handler))
        .route("/files", get(files::list_files_handler))
        .route("/files/upload", post(files::upload_handler))
        .route("/files/:id/download", get(files::download_handler))
        .route("/files/:id", delete(files::delete_handler))
        // ✅ rate limit lit l'état AppState
        .layer(middleware::from_fn_with_state(state.clone(), rate_limit_mw));

    Router::new()
        .nest("/api", api)
        .layer(cors)
        .with_state(state)
}
