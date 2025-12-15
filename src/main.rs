use axum::{
    body::Body,
    http::{HeaderValue, Method},
    response::IntoResponse,
    Router,
};
use sqlx::sqlite::SqlitePoolOptions;
use std::net::SocketAddr;
use tower_http::{cors::CorsLayer, trace::TraceLayer};

mod api;
use api::AppState;

#[tokio::main]
async fn main() {
    // DB
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "sqlite:///opt/jsecure-cloud/jsecure.db".to_string());
    let pool = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .expect("Impossible de se connecter à la base SQLite");
    let state = AppState { db: pool.clone() };

    // CORS
    let cors = CorsLayer::new()
        .allow_origin([
            HeaderValue::from_static("https://rust.jdoukh.org"),
            HeaderValue::from_static("http://rust.jdoukh.org"),
        ])
        .allow_methods([Method::GET, Method::POST, Method::DELETE, Method::OPTIONS])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
        ])
        .allow_credentials(true);

    // Router
    let app = Router::new()
        .nest("/api", api::api_router().with_state(state))
        .fallback(|req: axum::http::Request<Body>| async move {
            (axum::http::StatusCode::NOT_FOUND, format!("404: {}", req.uri()))
                .into_response()
        })
        .layer(cors)
        .layer(TraceLayer::new_for_http());

    // Ecoute sur toutes les interfaces pour Apache proxy
    let addr: SocketAddr = "0.0.0.0:8081".parse().expect("Adresse invalide");
    println!("J-Secure Cloud API sur http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("Impossible de binder le port 8081");

    // ✅ Un seul serve()
    axum::serve(listener, app).await.expect("Erreur serveur");
}
