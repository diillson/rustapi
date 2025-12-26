use actix_web::{dev::Payload, Error, FromRequest, HttpRequest};
use actix_web::error::ErrorUnauthorized;
use jsonwebtoken::{decode, DecodingKey, Validation, Algorithm};
use futures::future::{ready, Ready};
use crate::auth::Claims;

pub struct AuthenticatedUser {
    pub user_id: String,
}

impl FromRequest for AuthenticatedUser {
    type Error = Error;
    type Future = Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        let auth_header = req.headers().get("Authorization");
        if let Some(auth_header) = auth_header {
            if let Ok(auth_str) = auth_header.to_str() {
                if auth_str.starts_with("Bearer ") {
                    let token = &auth_str[7..];
                    let secret = std::env::var("JWT_SECRET").expect("JWT_SECRET must be set");
                    let mut validation = Validation::new(Algorithm::HS256);
                    validation.validate_exp = true;
                    validation.leeway = 0;
                    let token_data = decode::<Claims>(
                        token,
                        &DecodingKey::from_secret(secret.as_bytes()),
                        &validation,
                    );

                    if let Ok(token_data) = token_data {
                        return ready(Ok(AuthenticatedUser {
                            user_id: token_data.claims.sub,
                        }));
                    }
                }
            }
        }
        ready(Err( ErrorUnauthorized("Invalid token")))
    }
}
