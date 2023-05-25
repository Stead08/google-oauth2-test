use crate::handler::{
    get_me_handler, google_oauth_handler, login_user_handler, logout_handler, register_user_handler,
};
use crate::AppState;
use axum::http::HeaderValue;
use axum::response::IntoResponse;
use axum::response::Json;
use axum::routing::{get, post};
use axum::Router;
use hyper::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use hyper::Method;
use serde_json::json;
use tower_http::cors::CorsLayer;

pub fn create_router(state: AppState) -> Router {
    let api_router = api_router(state);

    //APIルーターを/apiにネスト
    Router::new().nest("/api", api_router)
}

pub fn api_router(state: AppState) -> Router {
    let cors_layer = CorsLayer::new()
        .allow_origin(state.domain.parse::<HeaderValue>().unwrap())
        .allow_methods(vec![Method::GET, Method::POST])
        .allow_headers(vec![CONTENT_TYPE, AUTHORIZATION, ACCEPT])
        .allow_credentials(true);

    let auth_router = Router::new()
        .route("/register", post(register_user_handler))
        .route("/login", post(login_user_handler))
        .route("/logout", get(logout_handler));

    let oauth_router = Router::new().route("/google", get(google_oauth_handler));

    let sessions_router = Router::new().nest("/oauth", oauth_router);

    let users_router = Router::new().route("/me", get(get_me_handler));

    Router::new()
        .nest("/auth", auth_router)
        .nest("/sessions", sessions_router)
        .nest("/users", users_router)
        .route("/health_check", get(health_check))
        .layer(cors_layer)
        .with_state(state)
}

pub async fn health_check() -> impl IntoResponse {
    const MESSAGE: &str = "How to Implement Google OAuth2 in Rust";

    Json(json!({"status": "success", "message": MESSAGE}))
}
