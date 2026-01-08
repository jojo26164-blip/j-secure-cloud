use std::net::SocketAddr;

use axum::Router;
use dotenvy::dotenv;
use sqlx::sqlite::SqlitePoolOptions;
use tracing::{error, info};
use tracing_subscriber::{fmt, EnvFilter};

use jsecure_cloud::api::{api_router, AppState};

#[derive(Debug)]
struct Cli {
    host: String,
    port: u16,
}

// parse simple sans crate externe
fn parse_cli() -> Cli {
    let mut host: Option<String> = None;
    let mut port: Option<u16> = None;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--host" => {
                if let Some(v) = args.next() {
                    host = Some(v);
                }
            }
            "--port" => {
                if let Some(v) = args.next() {
                    port = v.parse::<u16>().ok();
                }
            }
            _ => {}
        }
    }

    let host = host
        .or_else(|| std::env::var("HOST").ok())
        .unwrap_or_else(|| "127.0.0.1".to_string());

    let port = port
        .or_else(|| {
            std::env::var("PORT")
                .ok()
                .and_then(|s| s.parse::<u16>().ok())
        })
        .unwrap_or(8081);

    Cli { host, port }
}

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
    let database_url = std::env::var("DATABASE_URL").unwrap_or_else(|_| {
        eprintln!(
            "DATABASE_URL manquant (ex: sqlite:///opt/jsecure-cloud/data/db/jsecure.db?mode=rwc)"
        );
        std::process::exit(1);
    });

    let cli = parse_cli();

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

    // Migrations embarquées (source de vérité = repo au moment du build)
    sqlx::migrate!("./migrations")
        .run(&db)
        .await
        .unwrap_or_else(|e| {
            error!("migrations failed: {:?}", e);
            std::process::exit(1);
        });

    // State + Router
    let state = AppState { db };
    let app: Router = api_router(state);

    // Listener + serve (Axum 0.7)
    let addr: SocketAddr = format!("{}:{}", cli.host, cli.port)
        .parse()
        .unwrap_or_else(|_| {
            eprintln!("HOST/PORT invalides: {}:{}", cli.host, cli.port);
            std::process::exit(1);
        });

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| {
            eprintln!("Impossible de bind {}: {}", addr, e);
            std::process::exit(1);
        });

    info!("J-Secure Cloud API sur http://{}", addr);

    axum::serve(listener, app).await.unwrap();
}
