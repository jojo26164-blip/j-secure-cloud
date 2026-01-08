use axum::{
    extract::DefaultBodyLimit,
    http::{header, Method},
    middleware,
    routing::{delete, get, post},
    Router,
};
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;

pub mod admin;
pub mod audit;
pub mod auth;
pub mod error;
pub mod files;
pub mod health;
pub mod me;
pub mod rate_limit;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::SqlitePool,
}

fn cors_layer() -> CorsLayer {
    CorsLayer::new()
        // Origins autorisés (PAS "*", car credentials=true)
        .allow_origin([
            "https://jsecure-cloud.com".parse().unwrap(),
            "https://www.jsecure-cloud.com".parse().unwrap(),
            "https://upload.jsecure-cloud.com".parse().unwrap(),
        ])
        // Méthodes autorisées
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::DELETE,
            Method::OPTIONS,
        ])
        // Headers autorisés (ajoute RANGE + CONTENT_LENGTH pour download/upload)
        .allow_headers([
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
            header::ACCEPT,
            header::ORIGIN,
            header::RANGE,
            header::CONTENT_LENGTH,
        ])
        // Expose pour Range (sinon le browser ne voit pas Content-Range)
        .expose_headers([
            header::ACCEPT_RANGES,
            header::CONTENT_RANGE,
            header::CONTENT_LENGTH,
            header::CONTENT_TYPE,
            header::CONTENT_DISPOSITION,
        ])
        // Cookies cross-site
        .allow_credentials(true)
}

pub fn api_router(state: AppState) -> Router {
    let cors = cors_layer();

    let auth_layer = middleware::from_fn_with_state(state.clone(), auth::auth_middleware);
    let admin_layer = middleware::from_fn_with_state(state.clone(), admin::admin_middleware);

    let body_limit = DefaultBodyLimit::max(64 * 1024 * 1024usize);

    // =========================
    // PUBLIC
    // =========================
    let public = Router::new()
        .route("/health", get(health::health_handler))
        .route("/auth/login", post(auth::login_handler))
        .route("/auth/register", post(auth::register_handler))
        .route("/auth/logout", post(auth::logout_handler))
        .route("/auth/me", get(auth::me_handler))
        .layer(body_limit);

    // =========================
    // PROTECTED (logged-in)
    // =========================
    let protected = Router::new()
        .route("/files", get(files::list_files_handler))

        // IMPORTANT: :id = file_id (String) si ton files.rs est passé en file_id partout
        .route("/files/:id/download", get(files::download_handler))
        .route("/files/:id", delete(files::delete_handler))

        // Corbeille
        .route("/files/trash", get(files::trash_list_handler))
        .route("/files/:id/restore", post(files::restore_handler))
        .route("/files/:id/purge", delete(files::purge_handler))

        .route("/me", get(me::me_handler))
        .route_layer(auth_layer.clone())
        .layer(body_limit);

    // =========================
    // UPLOAD (logged-in + gros body limit)
    // =========================
    let upload = Router::new()
        .route("/files/upload", post(files::upload_handler))
        .route_layer(auth_layer.clone())
        .layer(DefaultBodyLimit::max(12 * 1024 * 1024 * 1024usize)); // 12 GiB

    // =========================
    // ADMIN
    // =========================
    let admin_routes = Router::new()
        .route("/admin/health", get(admin::health_handler))
        .route("/admin/stats", get(admin::stats_handler))
        .route("/admin/users", get(admin::users_handler))
        .route("/admin/users/:email/block", post(admin::block_user_handler))
        .route("/admin/users/:email/unblock", post(admin::unblock_user_handler))
        .route("/admin/users/:email/quota", post(admin::set_quota_handler))
        .route("/admin/users/:email/delete", post(admin::delete_user_handler))
        .route_layer(auth_layer)
        .route_layer(admin_layer)
        .layer(body_limit);

    Router::new()
        .nest("/api", public.merge(protected).merge(upload).merge(admin_routes))
        .nest_service("/", ServeDir::new("static"))
        .layer(cors)
        .with_state(state)
}
