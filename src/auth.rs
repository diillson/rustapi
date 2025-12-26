use actix_web::{web, HttpResponse, Responder};
use argon2::{password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString}, Argon2};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::AppState;

#[derive(Deserialize, ToSchema)]
pub struct RegisterUser {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize, ToSchema)]
pub struct LoginUser {
    pub username: String,
    pub password: String,
}

#[derive(Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
}

async fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default().hash_password(password.as_bytes(), &salt).map(|h| h.to_string())
}

async fn verify_password(password: &str, password_hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(password_hash)?;
    Argon2::default().verify_password(password.as_bytes(), &parsed_hash).map(|_| true).or_else(|_| Ok(false))
}

#[utoipa::path(post, path = "/auth/register", tag = "auth", request_body = RegisterUser, responses((status = 201, description = "User registered")))]
#[tracing::instrument(name = "register_user", skip(body, data))]
pub async fn register(body: web::Json<RegisterUser>, data: web::Data<AppState>) -> impl Responder {
    let user_id = Uuid::new_v4().to_string();
    let password_hash = hash_password(&body.password).await.unwrap();
    let now = Utc::now().to_rfc3339();
    let result = sqlx::query!("INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)", user_id, body.username, password_hash, now).execute(&data.db).await;
    match result {
        Ok(_) => HttpResponse::Created().finish(),
        Err(_) => HttpResponse::InternalServerError().body("Error"),
    }
}

#[utoipa::path(post, path = "/auth/login", tag = "auth", request_body = LoginUser, responses((status = 200, description = "User logged in")))]
#[tracing::instrument(name = "login_user", skip(body, data))]
pub async fn login(body: web::Json<LoginUser>, data: web::Data<AppState>) -> impl Responder {
    let user = sqlx::query!("SELECT id, password_hash FROM users WHERE username = ?", body.username).fetch_optional(&data.db).await;
    if let Ok(Some(user)) = user {
        if verify_password(&body.password, &user.password_hash).await.unwrap_or(false) {
            let expiration = Utc::now().checked_add_signed(Duration::hours(24)).unwrap().timestamp() as usize;
            let claims = Claims { sub: user.id, iat: Utc::now().timestamp() as usize,
            exp: expiration };
            let secret = std::env::var("JWT_SECRET").unwrap_or_else(|_| "secret".to_string());
            let token = encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())).unwrap();
            return HttpResponse::Ok().json(serde_json::json!({"token": token}));
        }
    }
    HttpResponse::Unauthorized().body("Invalid")
}
