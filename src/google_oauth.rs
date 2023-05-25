use crate::AppState;
use axum::extract::State;
use hyper::client::Client;
use hyper::header::AUTHORIZATION;
use hyper::{body::Buf, Body, Request, Uri};
use hyper_tls::HttpsConnector;
use serde::{Deserialize, Serialize};
use std::error::Error;

#[derive(Serialize, Deserialize)]
pub struct OAuthResponse {
    pub access_token: String,
    pub id_token: String,
}

#[derive(Deserialize)]
pub struct GoogleUserResult {
    pub id: String,
    pub email: String,
    pub verified_email: bool,
    pub name: String,
    pub given_name: String,
    pub family_name: String,
    pub picture: String,
    pub locale: String,
}

pub async fn request_token(
    authorization_code: String,
    State(state): State<AppState>,
) -> Result<OAuthResponse, Box<dyn Error + Send + Sync>> {
    let https = HttpsConnector::new();
    let client = Client::builder().build::<_, Body>(https);

    let params = [
        ("grant_type", "authorization_code"),
        ("redirect_uri", &state.env.google_oauth_redirect_url),
        ("client_id", &state.env.google_oauth_client_id),
        ("code", &authorization_code),
        ("client_secret", &state.env.google_oauth_client_secret),
    ];

    let uri: Uri = "https://oauth2.googleapis.com/token".parse()?;
    let body = serde_urlencoded::to_string(params)?;

    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/x-www-form-urlencoded")
        .body(Body::from(body))?;

    let response = client.request(request).await?;

    if response.status().is_success() {
        let bytes = hyper::body::to_bytes(response.into_body()).await?;
        let oauth_response: OAuthResponse = serde_json::from_slice(&bytes)?;
        Ok(oauth_response)
    } else {
        let message = "An error occurred while trying to retrieve access token.";
        Err(Box::new(std::io::Error::new(
            std::io::ErrorKind::Other,
            message,
        )))
    }
}

pub async fn get_google_user(
    access_token: &str,
    id_token: &str,
) -> Result<GoogleUserResult, Box<dyn Error + Send + Sync>> {
    let https = HttpsConnector::new();
    let client = Client::builder().build(https);

    let url = format!(
        "https://www.googleapis.com/oauth2/v1/userinfo?alt=json&access_token={}",
        access_token
    );

    let request = Request::builder()
        .uri(url)
        .method("GET")
        .header(AUTHORIZATION, format!("Bearer {}", id_token))
        .body(Body::empty())
        .unwrap();

    let res = client.request(request);

    match res.await {
        Ok(res) => {
            if res.status().is_success() {
                let body = hyper::body::aggregate(res).await?;
                let user_info = serde_json::from_reader(body.reader())?;
                Ok(user_info)
            } else {
                let message = "An error occurred while trying to retrieve user information.";
                Err(From::from(message))
            }
        }
        Err(e) => {
            let message = format!(
                "An error occurred while trying to retrieve user information. \n {}",
                e
            );
            Err(From::from(message))
        }
    }
}
