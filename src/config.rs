// src/config.rs

use std::{env, net::SocketAddr};

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
}

impl AppConfig {
    pub fn from_env() -> Self {
        // APP_HOST : optionnel, sinon 0.0.0.0
        let host = env::var("APP_HOST")
            .ok()
            .unwrap_or_else(|| "0.0.0.0".to_string());

        // APP_PORT : optionnel, sinon 9000
        let port = env::var("APP_PORT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(9200);

        Self { host, port }
    }

    pub fn socket_addr(&self) -> SocketAddr {
        format!("{}:{}", self.host, self.port)
            .parse()
            .expect("config addr invalid")
    }
}
