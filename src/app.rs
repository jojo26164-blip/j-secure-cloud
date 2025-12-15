use axum::Router;

use crate::{api, web};

pub fn build_app() -> Router {
    Router::new()
        .nest("/api", api::router())
        .nest("/", web::router())
}
