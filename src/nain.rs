mod db;
mod api;

use axum::{serve, Router};
use tokio::net::TcpListener;
use crate::db::AppState;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    // État global (pool SQLite)
    let state = AppState::new()
        .await
        .expect("❌ Impossible d'initialiser SQLite");

    // Router complet (API + page /)
    let app: Router<AppState> = api::api_router(state);

    // Serveur TCP
    let listener = TcpListener::bind("0.0.0.0:9200")
        .await
        .expect("❌ Impossible d’ouvrir le port 9200");

    println!("🚀 J-Secure Cloud sur : http://192.168.1.211:9200");

    // Axum 0.7 : c’est OK comme ça
    serve(listener, app)
        .await
        .unwrap();
}
