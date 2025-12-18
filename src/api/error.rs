use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized,
    Forbidden,
    NotFound,
    VirusDetected,
    FileRefused,
    Internal,
}

impl ApiError {
    pub fn bad_request<M: Into<String>>(msg: M) -> Self {
        ApiError::BadRequest(msg.into())
    }

    pub fn unauthorized() -> Self {
        ApiError::Unauthorized
    }

    pub fn forbidden() -> Self {
        ApiError::Forbidden
    }

    pub fn not_found() -> Self {
        ApiError::NotFound
    }

    pub fn virus_detected() -> Self {
        ApiError::VirusDetected
    }

    pub fn file_refused() -> Self {
        ApiError::FileRefused
    }

    pub fn internal() -> Self {
        ApiError::Internal
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "Non autorisé".to_string()),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "Accès interdit".to_string()),
            ApiError::NotFound => (StatusCode::NOT_FOUND, "Introuvable".to_string()),
            ApiError::VirusDetected => (
                StatusCode::BAD_REQUEST,
                "Fichier infecté détecté".to_string(),
            ),
            ApiError::FileRefused => (
                StatusCode::BAD_REQUEST,
                "Type de fichier interdit".to_string(),
            ),
            ApiError::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Erreur serveur".to_string(),
            ),
        };

        let body = Json(json!({
            "error": status.as_str(),
            "message": message
        }));

        (status, body).into_response()
    }
}
