use axum::{
    extract::DefaultBodyLimit,
    http::{HeaderValue, Method},
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::CorsLayer;

pub mod auth;
pub mod error;
pub mod files;
pub mod health;
pub mod rate_limit;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::SqlitePool,
}

fn cors_layer() -> CorsLayer {
    let origins = std::env::var("CORS_ORIGINS").unwrap_or_default();

    if origins.trim().is_empty() {
        // DEV: open CORS
        return CorsLayer::new()
            .allow_origin(tower_http::cors::Any)
            .allow_methods([Method::GET, Method::POST, Method::DELETE])
            .allow_headers(tower_http::cors::Any);
    }

    // PROD: strict allowlist
    let allowed: Vec<HeaderValue> = origins
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse::<HeaderValue>().ok())
        .collect();

    CorsLayer::new()
        .allow_origin(allowed)
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ])
}

pub fn api_router(state: AppState) -> Router {
    let cors = cors_layer();

    // ⚠️ Limite globale (large, pour ne pas casser les autres routes)
    let body_limit = DefaultBodyLimit::max(64 * 1024 * 1024); // 64 MiB

    // ✅ Limite upload contrôlée par env (B5)
    let max_upload: usize = std::env::var("MAX_UPLOAD_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2 * 1024 * 1024); // 2 MiB par défaut

    let public = Router::new()
        .route("/health", get(health::health_handler))
        .route("/auth/login", post(auth::login_handler))
        .route("/auth/register", post(auth::register_handler));

    let protected = Router::new()
        .route("/files", get(files::list_files_handler))
        .route("/files/:id/download", get(files::download_handler))
        .route("/files/:id", delete(files::delete_handler));

    // ✅ Upload séparé + marge pour que Axum ne coupe pas avant ton 413
    let upload = Router::new()
        .route("/files/upload", post(files::upload_handler))
        .layer(DefaultBodyLimit::max(max_upload + 1024 * 1024)); // +1MiB marge

    Router::new()
        .nest("/api", public.merge(protected).merge(upload))
        .layer(cors)
        .layer(body_limit)
        .with_state(state)
}
