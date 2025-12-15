use tracing::warn;
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use crate::api::error::ApiError;

#[derive(Clone)]
pub struct RateLimiter {
    map: Arc<DashMap<String, (u32, Instant)>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self { map: Arc::new(DashMap::new()) }
    }

    fn hit(&self, key: String, max: u32, window: Duration) -> Result<(), ApiError> {
        let now = Instant::now();
        let mut entry = self.map.entry(key).or_insert((0, now));
        let (count, start) = entry.value_mut();

        if now.duration_since(*start) > window {
            *count = 0;
            *start = now;
        }

        *count += 1;
        if *count > max {
            return Err(ApiError::new(
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "Trop de requêtes, réessaie plus tard",
            ));
        }
        Ok(())
    }
}

// Cloudflare -> cf-connecting-ip ; sinon x-forwarded-for ; sinon unknown
fn client_ip(headers: &HeaderMap) -> String {
    if let Some(v) = headers.get("cf-connecting-ip").and_then(|v| v.to_str().ok()) {
        return v.trim().to_string();
    }
    if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        return v.split(',').next().unwrap_or("unknown").trim().to_string();
    }
    "unknown".to_string()
}

// ✅ Axum 0.7: Next pas générique, Request = Request<Body>
pub async fn rate_limit_mw(
    State(limiter): State<RateLimiter>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let ip = client_ip(req.headers());

    let (max, window) = if path.starts_with("/auth/login") {
        (5, Duration::from_secs(60))
    } else if path.starts_with("/auth/register") {
        (3, Duration::from_secs(60))
    } else if path.starts_with("/files/upload") {
        (10, Duration::from_secs(600))
    } else if path.contains("/download") {
        (60, Duration::from_secs(60))
    } else if path.starts_with("/files/") {
        (30, Duration::from_secs(60))
    } else {
        (120, Duration::from_secs(60))
    };

    let key = format!("{ip}|{path}");

    if let Err(e) = limiter.hit(key, max, window) {
    // 🔒 LOG SÉCURITÉ : rate limit déclenché
    println!(
        "[SECURITY][RATE_LIMIT] ip={} path={} max={} window={}s",
        ip,
        path,
        max,
        window.as_secs()
    );
  
    warn!(ip = %ip, path = %path, max = max, window_secs = window.as_secs(), "rate_limited");
    return e.into_response();
}

    next.run(req).await
}
