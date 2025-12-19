use axum::{
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::{Any, CorsLayer};

pub mod auth;
pub mod error;
pub mod files;
pub mod health;
// pub mod rate_limit; // (on l'activera après quand ce sera stable)

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::SqlitePool,
}

pub fn api_router(state: AppState) -> Router {
    // CORS (dev friendly). En prod tu mettras une origin stricte.
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // ✅ Routes publiques (pas besoin de token)
    let public = Router::new()
        .route("/health", get(health::health_handler))
        .route("/auth/login", post(auth::login_handler))
        .route("/auth/register", post(auth::register_handler));

    // ✅ Routes protégées (token requis)
    // (la protection se fait DANS les handlers via get_user_from_headers)
    let protected = Router::new()
        .route("/files", get(files::list_files_handler))
        .route("/files/upload", post(files::upload_handler))
        .route("/files/:id/download", get(files::download_handler))
        .route("/files/:id", delete(files::delete_handler));

    // ✅ API finale: /api/...
    Router::new()
        .nest("/api", public.merge(protected))
        .layer(cors)
        .with_state(state)
}
