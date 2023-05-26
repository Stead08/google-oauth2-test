use crate::google_oauth::{get_google_user, request_token};
use crate::model::{LoginUserSchema, QueryCode, TokenClaims, User};
use crate::response::{FilteredUser, UserData, UserResponse};
use crate::{model::RegisterUserSchema, AppState};
use axum::extract::{Query, State};
use axum::http::{HeaderName, HeaderValue};
use axum::response::{AppendHeaders, IntoResponse};
use axum::{debug_handler, Json};
use axum_extra::extract::cookie::Cookie;
use axum_extra::extract::{CookieJar};
use chrono::Utc;
use hyper::header::LOCATION;
use hyper::StatusCode;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde_json::{json, Value};
use time::Duration;
use uuid::Uuid;

pub fn user_to_response(user: &User) -> FilteredUser {
    FilteredUser {
        id: user.id.to_owned().unwrap(),
        name: user.name.to_owned(),
        email: user.email.to_owned(),
        verified: user.verified.to_owned(),
        photo: user.photo.to_owned(),
        provider: user.provider.to_owned(),
        role: user.role.to_owned(),
        createdAt: user.createdAt.unwrap(),
        updatedAt: user.updatedAt.unwrap(),
    }
}

pub async fn register_user_handler(
    State(state): State<AppState>,
    Json(body): Json<RegisterUserSchema>,
) -> impl IntoResponse {
    let mut vec = state.db.lock().await;

    let user = vec.iter().find(|user| user.email == body.email);

    if user.is_some() {
        return (
            StatusCode::CONFLICT,
            Json(json!({"status": "fail", "message": "Email already exist"})),
        );
    }

    let uuid_id = Uuid::new_v4();
    let datetime = Utc::now();

    let user = User {
        id: Some(uuid_id.to_string()),
        name: body.name.to_owned(),
        verified: false,
        email: body.email.to_owned().to_lowercase(),
        provider: "local".to_string(),
        role: "user".to_string(),
        password: "".to_string(),
        photo: "default.png".to_string(),
        createdAt: Some(datetime),
        updatedAt: Some(datetime),
    };

    vec.push(user.to_owned());

    let json_response = UserResponse {
        status: "success".to_string(),
        data: UserData {
            user: user_to_response(&user),
        },
    };

    (StatusCode::OK, Json(json!(json_response)))
}

pub async fn login_user_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(body): Json<LoginUserSchema>,
) -> Result<(CookieJar, (StatusCode, Json<Value>)), impl IntoResponse> {
    let vec = state.db.lock().await;

    let user = vec
        .iter()
        .find(|user| user.email == body.email.to_lowercase());

    if user.is_none() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"status":"fail", "message": "Invalid email of password"})),
        ));
    }

    let user = user.unwrap().clone();

    if user.provider == "Google" {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"status": "fail", "message": "Use Google OAuth2 instead"})),
        ));
    }

    let jwt_secret = state.env.jwt_secret;
    let now = Utc::now();
    let iat = now.timestamp() as usize;
    let exp = (now + chrono::Duration::minutes(state.env.jwt_max_age)).timestamp() as usize;
    let claims = TokenClaims {
        sub: user.id.unwrap(),
        iat,
        exp,
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_ref()),
    )
    .expect("Failed to encode token");

    let cookie = Cookie::build("token", token)
        .path("/")
        .max_age(Duration::seconds(60 * state.env.jwt_max_age))
        .http_only(true)
        .finish();

    Ok((
        jar.add(cookie),
        (StatusCode::OK, Json(json!({"status": "success"}))),
    ))
}
#[debug_handler]
pub async fn google_oauth_handler(
    State(state): State<AppState>,
    jar: CookieJar,
    query: Query<QueryCode>,
) -> Result<
    (
        CookieJar,
        (StatusCode, AppendHeaders<[(HeaderName, HeaderValue); 1]>),
    ),
    (StatusCode, Json<Value>),
> {
    let code = query.code.clone();
    let status = query.state.clone();

    if code.is_empty() {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"status": "fail", "message": "Authorization code not provided"})),
        ));
    }

    let token_response = request_token(code, State(state.clone())).await;

    match token_response {
        Ok(token_response) => {
            let google_user =
                get_google_user(&token_response.access_token, &token_response.id_token).await;
            match google_user {
                Ok(google_user) => {
                    let mut vec = state.db.lock().await;
                    let email = google_user.email.to_lowercase();
                    let user_id: String;

                    if let Some(user) = vec.iter_mut().find(|user| user.email == email) {
                        user_id = user.id.to_owned().unwrap();
                        user.email = email.to_owned();
                        user.photo = google_user.picture;
                        user.updatedAt = Some(Utc::now());
                    } else {
                        let datetime = Utc::now();
                        let id = Uuid::new_v4();
                        user_id = id.to_owned().to_string();
                        let user_data = User {
                            id: Some(id.to_string()),
                            name: google_user.name,
                            email,
                            password: "".to_string(),
                            role: "user".to_string(),
                            photo: google_user.picture,
                            verified: google_user.verified_email,
                            provider: "Google".to_string(),
                            createdAt: Some(datetime),
                            updatedAt: Some(datetime),
                        };

                        vec.push(user_data)
                    }
                    let jwt_secret = state.env.jwt_secret.to_owned();
                    let now = Utc::now();
                    let iat = now.timestamp() as usize;
                    let exp = (now + chrono::Duration::minutes(state.env.jwt_max_age)).timestamp()
                        as usize;
                    let claims = TokenClaims {
                        sub: user_id,
                        iat,
                        exp,
                    };

                    let token = encode(
                        &Header::default(),
                        &claims,
                        &EncodingKey::from_secret(jwt_secret.as_ref()),
                    )
                    .expect("failed to encode token");

                    let cookie = Cookie::build("token", token)
                        .path("/")
                        .max_age(Duration::seconds(60 * state.env.jwt_max_age))
                        .finish();

                    let frontend_origin = state.env.client_origin.to_owned();
                    Ok((
                        jar.add(cookie),
                        (
                            StatusCode::FOUND,
                            AppendHeaders([(
                                LOCATION,
                                format!("{}{}", frontend_origin, status).parse().unwrap(),
                            )]),
                        ),
                    ))
                }
                Err(error) => {
                    let message = error.to_string();
                    Err((
                        StatusCode::BAD_GATEWAY,
                        Json(json!({"status": "fail", "message": message})),
                    ))
                }
            }
        }
        Err(error) => {
            let message = error.to_string();
            Err((
                StatusCode::BAD_GATEWAY,
                Json(json!({"status": "fail", "message": message})),
            ))
        }
    }
}

pub async fn logout_handler(
    jar: CookieJar
) -> impl IntoResponse {
    let cookie = Cookie::build("token", "")
        .path("/")
        .finish();
    (
        StatusCode::OK,
        jar.remove(cookie),
        Json(json!({"status": "success"})),
    ).into_response()
}

pub async fn get_me_handler(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    let vec = state.db.lock().await;
    let token = jar.get("token");

    match token {
        Some(token) => {
            let token = token.value().to_owned();
            let jwt_secret = state.env.jwt_secret.to_owned();
            let token_data = decode::<TokenClaims>(
                &token,
                &DecodingKey::from_secret(jwt_secret.as_ref()),
                &Validation::default(),
            );

            match token_data {
                Ok(token_data) => {
                    let user = vec
                        .iter()
                        .find(|user| user.id == Some(token_data.claims.sub.to_owned()));

                    if user.is_none() {
                        return (
                            StatusCode::NOT_FOUND,
                            Json(json!({"status": "fail", "message": "User not found"})),
                        );
                    }

                    let user = user.unwrap();

                    (
                        StatusCode::OK,
                        Json(json!({
                    "status": "success",
                    "data": {
                        "user": user_to_response(user)
                    }
                })),
                    )
                }
                Err(_) => (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"status": "fail", "message": "Invalid token"})),
                ),
            }
        },
        None => {
            (StatusCode::UNAUTHORIZED, Json(json!({"status": "login required"})))
        }
    }


}
