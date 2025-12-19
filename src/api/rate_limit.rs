use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, Request},
    middleware::Next,
    response::{IntoResponse, Response},
};
use dashmap::DashMap;
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::warn;

use crate::api::error::ApiError;

#[derive(Clone)]
pub struct RateLimiter {
    map: Arc<DashMap<String, (u32, Instant)>>,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            map: Arc::new(DashMap::new()),
        }
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
            return Err(ApiError::rate_limited(
                "RATE_LIMIT: trop de requêtes, réessaie plus tard",
            ));
        }

        Ok(())
    }
}

fn client_ip(headers: &HeaderMap) -> String {
    if let Some(v) = headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
    {
        return v.trim().to_string();
    }
    if let Some(v) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        return v.split(',').next().unwrap_or("unknown").trim().to_string();
    }
    "unknown".to_string()
}

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
    } else if path.starts_with("/files/") {
        (60, Duration::from_secs(60))
    } else {
        (120, Duration::from_secs(60))
    };

    let key = format!("{ip}|{path}");
    if let Err(e) = limiter.hit(key, max, window) {
        warn!(ip = %ip, path = %path, max = max, window_secs = window.as_secs(), "rate_limited");
        return e.into_response();
    }

    next.run(req).await
}
