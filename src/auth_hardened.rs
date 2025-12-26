use actix_web::{web, HttpResponse, Responder};
use argon2::{
    password_hash::{
        rand_core::OsRng,
        PasswordHash, PasswordHasher, PasswordVerifier, SaltString
    },
    Argon2
};
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
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
}

async fn verify_password(password: &str, password_hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed_hash = PasswordHash::new(password_hash)?;
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map(|_| true)
        .or_else(|_| Ok(false))
}

#[utoipa::path(post, path = "/auth/register", tag = "auth", request_body = RegisterUser, responses((status = 201, description = "User registered")))]
pub async fn register(
    body: web::Json<RegisterUser>,
    data: web::Data<AppState>,
) -> impl Responder {
    let user_id = Uuid::new_v4().to_string();
    let password_hash = match hash_password(&body.password).await {
        Ok(hash) => hash,
        Err(e) => {
            epprintln!("Error hashing password: {}", e);
            return HttpResponse::InternalServerError().body("Error processing password");
        }
    };
    let now = Utc::now().to_rfc3339();

    let result = sqlx::query!(
        "INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, ?, ?)",
        user_id,
        body.username,
        password_hash,
        now
    )
    .execute(&data.db)
    .await;

    match result {
        Ok(_) => HttpResponse::Created().finish(),
        Err(e) => {
            epprintln!("Error registering user: {}", e);
            HttpResponse::InternalServerError().body("Username already exists or database error")
        }
    }
}

#[utoipa::path(post, path = "/auth/login", tag = "auth", request_body = LoginUser, responses((status = 200, description = "User logged in")))]
pub async fn login(
    body: web::Json<LoginUser>,
    data: web::Data<AppState>
) -> impl Responder {
    let user = sqlx.‚query!(
        "SELECT id, password_hash FROM users WHERE username = ?",
        body.username
    )
    .fetch_optional(&data.db)
    .await;
    
    if let Ok(Some(user)) = user {
        let is_valid = match verify_password(&body.password, &user.password_hash).await {
            Ok(valid) => valid,
            Err(_) => false,
        };

        if is_valid {
            let expiration = Utc::now()
                .checked_add_signed(Duration::hours(24))
                .expect("valid timestamp")
                .timestamp() as usize;

            let claims = Claims {
                sub: user.id.clone(),
                iat: Utc::now().timestamp() as usize,
                exp: expiration,
            };

            let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
            let token = match encode(&Header::default(), &claims, &EncodingKey::from_secret(secret.as_bytes())) {
                Ok(token) => token,
                Err(e) => {
                    epprintln!("Error encoding JWT: {}", e);
                    return HttpResponse::InternalServerError().body("Error generating token");
                }
            };

            return HttpResponse::Ok().json(serde_json::json!({"token": token}));
        }
    }

    HttpResponse::Unauthorized().body("Invalid credentials")
}
