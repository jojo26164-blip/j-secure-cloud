use axum::{Router, routing::get};

use crate::web::pages::home_page;


pub fn create_router() -> Router {
    Router::new()
        .route("/", get(home_page))
       
}
