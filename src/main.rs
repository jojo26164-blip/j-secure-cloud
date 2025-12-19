use std::net::SocketAddr;

use axum::Router;
use dotenvy::dotenv;
use sqlx::sqlite::SqlitePoolOptions;
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};

use jsecure_cloud::api::{api_router, AppState};

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    init_tracing();

    // ENV
    let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL manquant");
    let host = std::env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port: u16 = std::env::var("PORT")
        .unwrap_or_else(|_| "8081".to_string())
        .parse()
        .expect("PORT invalide");

    // DB
    let db = SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&database_url)
        .await
        .unwrap_or_else(|e| {
            error!("Impossible de se connecter à SQLite: {}", e);
            std::process::exit(1);
        });

    info!("Connexion SQLite OK");

    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .expect("migrations failed");

    // State + Router

    let state = AppState { db };
    let app: Router = api_router(state);

    // Listener + serve (Axum 0.7)
    let addr: SocketAddr = format!("{host}:{port}").parse().expect("HOST invalide");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    info!("J-Secure Cloud API sur http://{}", addr);

    axum::serve(listener, app).await.unwrap();
}
