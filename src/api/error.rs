use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    pub error: &'static str,
    pub message: &'static str,
}

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    pub body: ErrorBody,
}

impl ApiError {
    pub fn new(status: StatusCode, error: &'static str, message: &'static str) -> Self {
        Self { status, body: ErrorBody { error, message } }
    }

    // Helpers (à utiliser partout)
    pub fn bad_request(message: &'static str) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "bad_request", message)
    }
    pub fn unauthorized() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "unauthorized", "Non autorisé")
    }
    pub fn session_expired() -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "session_expired", "Session expirée, reconnecte-toi")
    }
    pub fn file_refused() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "file_refused", "Fichier refusé pour sécurité")
    }
    pub fn virus_detected() -> Self {
        Self::new(StatusCode::BAD_REQUEST, "virus_detected", "Fichier bloqué par l'antivirus")
    }
    pub fn file_too_large() -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "file_too_large", "Fichier trop volumineux")
    }
    pub fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "Erreur serveur")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

// Type alias pratique
pub type ApiResult<T> = Result<T, ApiError>;
