use sqlx::sqlite::{SqlitePoolOptions};
use sqlx::SqlitePool;
use std::path::Path;

#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
}

impl AppState {
    pub async fn new() -> Result<Self, sqlx::Error> {
        // 1) S'assurer que le dossier data/ existe
        let data_dir = Path::new("data");
        if !data_dir.exists() {
            std::fs::create_dir_all(data_dir)
                .expect("❌ Impossible de créer le dossier data/");
        }

        // 2) Chemin du fichier SQLite
        let db_path = data_dir.join("jsecure-cloud.db");

        // 3) Créer le fichier s'il n'existe pas (sans passer par SQLx)
        std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .open(&db_path)
            .expect("❌ Impossible de créer ou ouvrir le fichier jsecure-cloud.db");

        // 4) Connexion SQLite avec CHEMIN SIMPLE (PAS de sqlite://)
        let db_str = db_path.to_string_lossy().to_string();
        println!("🔧 SQLite DB file: {}", db_str);

        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(&db_str)
            .await?;

        // 5) Table users
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            );
            "#,
        )
        .execute(&pool)
        .await?;

        // 6) Table files
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS files (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                owner      TEXT NOT NULL,
                filename   TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                created_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&pool)
        .await?;

        println!("✅ Base SQLite initialisée dans {}", db_path.display());

        Ok(Self { db: pool })
    }
}
