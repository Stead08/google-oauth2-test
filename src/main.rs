mod config;
mod google_oauth;
mod handler;
mod model;
mod response;
mod router;

use crate::model::User;
use crate::router::create_router;
use dotenv::dotenv;
use log::info;
use std::env;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(Debug, Clone)]
pub struct AppState {
    pub db: Arc<Mutex<Vec<User>>>,
    pub env: config::Config,
    pub domain: String,
}

impl AppState {
    pub fn init() -> AppState {
        AppState {
            db: Arc::new(Mutex::new(Vec::new())),
            env: config::Config::init(),
            domain: env::var("CLIENT_ORIGIN").unwrap(),
        }
    }
}

#[tokio::main]
async fn main() {
    if std::env::var_os("RUST_LOG").is_none() {
        std::env::set_var(
            "RUST_LOG",
            "example_print_request_response=debug,tower_http=debug",
        )
    }
    tracing_subscriber::fmt::init();
    dotenv().ok();

    let state = AppState::init();
    let app = create_router(state);
    //run it with hyper on localhost:8000
    info!("Listening on port:8000");
    axum::Server::bind(&"0.0.0.0:8000".parse().unwrap())
        .serve(app.into_make_service())
        .await
        .unwrap();
}
