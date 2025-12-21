use axum::http::HeaderMap;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::time::{Duration, Instant};

use crate::api::error::{ApiError, ApiResult};

static RL: Lazy<DashMap<String, Bucket>> = Lazy::new(DashMap::new);

#[derive(Clone, Debug)]
struct Bucket {
    count: u32,
    window_start: Instant,
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

/// Rate limit mémoire: (ip + key) -> limit par fenêtre.
/// Retourne ApiError::rate_limited si dépassé.
pub fn rate_limit_or_err(
    headers: &HeaderMap,
    key: &str,
    limit: u32,
    window: Duration,
) -> ApiResult<()> {
    let ip = client_ip(headers);
    let k = format!("{key}:{ip}");
    let now = Instant::now();

    let mut entry = RL.entry(k).or_insert(Bucket {
        count: 0,
        window_start: now,
    });

    // reset fenêtre si expirée
    if now.duration_since(entry.window_start) >= window {
        entry.window_start = now;
        entry.count = 0;
    }

    entry.count += 1;

    if entry.count > limit {
        return Err(ApiError::rate_limited(
            "Trop de tentatives. Réessaie dans une minute.",
        ));
    }

    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, StatusCode};

    fn headers_with_ip(ip: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", ip.parse().unwrap());
        h
    }

    #[test]
    fn rate_limit_blocks_after_limit() {
        let headers = headers_with_ip("1.2.3.4");

        // limit=3 sur 60s => 4ème doit bloquer
        assert!(rate_limit_or_err(&headers, "upload", 3, Duration::from_secs(60)).is_ok());
        assert!(rate_limit_or_err(&headers, "upload", 3, Duration::from_secs(60)).is_ok());
        assert!(rate_limit_or_err(&headers, "upload", 3, Duration::from_secs(60)).is_ok());

        let err = rate_limit_or_err(&headers, "upload", 3, Duration::from_secs(60)).unwrap_err();

        // err est un ApiError
        assert_eq!(err.status, StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn rate_limit_is_per_key() {
        let headers = headers_with_ip("9.9.9.9");

        for _ in 0..3 {
            assert!(rate_limit_or_err(&headers, "login", 3, Duration::from_secs(60)).is_ok());
        }

        // upload doit rester OK car clé différente
        assert!(rate_limit_or_err(&headers, "upload", 3, Duration::from_secs(60)).is_ok());
    }
}
