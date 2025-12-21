use axum::{
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::CorsLayer;

// ✅ IMPORTANT: pas "use http::..." -> ça t'a cassé
use axum::http::{HeaderValue, Method};

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
    // Exemple: "http://127.0.0.1:5500,http://localhost:5500,https://tondomaine.com"
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

    let public = Router::new()
        .route("/health", get(health::health_handler))
        .route("/auth/login", post(auth::login_handler))
        .route("/auth/register", post(auth::register_handler));

    let protected = Router::new()
        .route("/files", get(files::list_files_handler))
        .route("/files/upload", post(files::upload_handler))
        .route("/files/:id/download", get(files::download_handler))
        .route("/files/:id", delete(files::delete_handler));

    Router::new()
        .nest("/api", public.merge(protected))
        .layer(cors)
        .with_state(state)
}
