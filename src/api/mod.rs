use axum::{
    extract::DefaultBodyLimit,
    http::{HeaderValue, Method},
    middleware,
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;

pub mod admin;
pub mod auth;
pub mod error;
pub mod files;
pub mod health;
pub mod me;
pub mod rate_limit;
pub mod audit;

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
    let auth_layer = middleware::from_fn_with_state(state.clone(), auth::auth_middleware);

    // Limite globale (hors upload) : 64 MiB
    let body_limit = DefaultBodyLimit::max(64 * 1024 * 1024usize);

    let public = Router::new()
        .route("/health", get(health::health_handler))
        .route("/auth/login", post(auth::login_handler))
        .route("/auth/register", post(auth::register_handler))
        .route("/auth/logout", post(auth::logout_handler))
        .route("/auth/me", get(auth::me_handler))
        .layer(body_limit);

    let protected = Router::new()
        .route("/files", get(files::list_files_handler))
        .route("/files/:id/download", get(files::download_handler))
        .route("/me", get(me::me_handler))
        .route("/files/:id", delete(files::delete_handler))

        // admin
        .route("/admin/stats", get(admin::stats_handler))
        .route("/admin/users", get(admin::users_handler))
        .route("/admin/users/:email/block", post(admin::block_user_handler))
        .route(
            "/admin/users/:email/unblock",
            post(admin::unblock_user_handler),
        )
        .route("/admin/users/:email/quota", post(admin::set_quota_handler))
        .route_layer(auth_layer.clone())
        .layer(body_limit);

    // Upload séparé
    let upload = Router::new()
        .route("/files/upload", post(files::upload_handler))
        .route_layer(auth_layer)
        .layer(DefaultBodyLimit::max(6 * 1024 * 1024 * 1024usize)); // 6 GiB

    Router::new()
        .nest("/api", public.merge(protected).merge(upload))
        .nest_service("/", ServeDir::new("static"))
        .layer(cors)
        .with_state(state)
}
