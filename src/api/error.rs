use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;

pub type ApiResult<T> = Result<T, ApiError>;

#[derive(Debug, Serialize, Clone)]
pub struct ApiErrorBody {
    pub error: &'static str,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct ApiError {
    pub status: StatusCode,
    pub body: ApiErrorBody,
}

impl ApiError {
    pub fn new(status: StatusCode, error: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            body: ApiErrorBody {
                error,
                message: message.into(),
            },
        }
    }

    // 413
    pub fn payload_too_large(message: impl Into<String>) -> Self {
        Self::new(StatusCode::PAYLOAD_TOO_LARGE, "PAYLOAD_TOO_LARGE", message)
    }

    // 507
    pub fn insufficient_storage(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::INSUFFICIENT_STORAGE,
            "INSUFFICIENT_STORAGE",
            message,
        )
    }

    // 403 quota
    pub fn quota_exceeded(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "QUOTA_EXCEEDED", message)
    }

    // 400
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, "BAD_REQUEST", message)
    }

    // 401
    pub fn unauthorized() -> Self {
        Self::new(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "token manquant ou invalide",
        )
    }

    pub fn unauthorized_msg(message: impl Into<String>) -> Self {
        Self::new(StatusCode::UNAUTHORIZED, "UNAUTHORIZED", message)
    }

    // 403
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, "FORBIDDEN", message)
    }

    pub fn forbidden_default() -> Self {
        Self::forbidden("forbidden")
    }

    // 404
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "NOT_FOUND", message)
    }

    // 409
    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, "CONFLICT", message)
    }

    // 429
    pub fn rate_limited(message: impl Into<String>) -> Self {
        Self::new(StatusCode::TOO_MANY_REQUESTS, "RATE_LIMIT", message)
    }

    // 500
    pub fn internal() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            "INTERNAL",
            "erreur interne",
        )
    }

    pub fn internal_msg(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "INTERNAL", message)
    }

    // Fichiers
    pub fn file_refused() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "FILE_REFUSED",
            "type de fichier interdit",
        )
    }

    pub fn virus_detected() -> Self {
        Self::new(
            StatusCode::BAD_REQUEST,
            "VIRUS_DETECTED",
            "fichier infecté détecté",
        )
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

// Helper sqlx
pub fn db_err(context: &'static str, e: sqlx::Error) -> ApiError {
    ApiError::internal_msg(format!("Erreur DB ({context}): {e}"))
}
