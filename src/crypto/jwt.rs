use crate::{
    config::JwtConfig,
    error::{AuthError, Result},
};
use base64::prelude::*;
use chrono::Utc;
use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use secrecy::ExposeSecret;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// JWT claims structure for authenticated sessions
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Claims {
    /// User identifier/public key hash
    pub sub: Uuid,
    /// Expiration timestamp (Unix timestamp)
    pub exp: i64,
    /// Issued at timestamp (Unix timestamp)
    pub iat: i64,
}

/// Creates a signed JWT token for an authenticated session
///
/// # Arguments
/// * `session_id` - Unique session identifier
/// * `config` - JWT configuration with secret and TTL
///
/// # Returns
/// * `Ok(String)` - Signed JWT token
/// * `Err(AuthError)` - Base64 or JWT encoding error
///
/// # Example
/// ```rust
/// use uuid::Uuid;
/// use secrecy::Secret;
/// use base64::prelude::*;
/// use ecdsa_jwt::crypto::jwt::create_jwt;
/// use ecdsa_jwt::config::JwtConfig;
///
/// let config = JwtConfig {
///     secret: Secret::new(BASE64_STANDARD.encode("secret-key")),
///     ttl: 3600, // 1 hour
/// };
/// let session_id = Uuid::new_v4();
/// let token = create_jwt(session_id, &config);
/// ```
pub fn create_jwt(session_id: Uuid, config: &JwtConfig) -> Result<String> {
    let jwt_secret = decode_secret(config.secret.expose_secret())?;
    let now = Utc::now().timestamp();
    let claims = Claims {
        sub: session_id,
        exp: now + config.ttl,
        iat: now,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(&jwt_secret),
    )
    .map_err(|e| AuthError::JwtError(format!("Failed to create JWT: {}", e)))?;

    Ok(token)
}

/// Validates a JWT token and extracts the claims
///
/// # Arguments
/// * `token` - JWT token string to validate
/// * `config` - JWT configuration with secret for verification
///
/// # Returns
/// * `Ok(Claims)` - Validated claims containing session info
/// * `Err(AuthError)` - Token expired, invalid signature, malformed, or decode error
///
/// # Example
/// ```rust
/// use secrecy::Secret;
/// use base64::prelude::*;
/// use ecdsa_jwt::crypto::jwt::validate_token;
/// use ecdsa_jwt::config::JwtConfig;
///
/// let config = JwtConfig {
///     secret: Secret::new(BASE64_STANDARD.encode("secret-key")),
///     ttl: 3600,
/// };
/// let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...";
/// let claims = validate_token(token, &config);
/// ```
pub fn validate_token(token: &str, config: &JwtConfig) -> Result<Claims> {
    let jwt_secret = decode_secret(config.secret.expose_secret())?;
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(&jwt_secret),
        &Validation::new(Algorithm::HS256),
    )
    .map_err(|e| match e.kind() {
        jsonwebtoken::errors::ErrorKind::ExpiredSignature => AuthError::ExpiredToken,
        jsonwebtoken::errors::ErrorKind::InvalidSignature => AuthError::InvalidChallenge,
        jsonwebtoken::errors::ErrorKind::InvalidToken => AuthError::InvalidToken,
        _ => AuthError::JwtError(format!("JWT validation failed: {}", e)),
    })?;
    let claims = token_data.claims;
    if claims.exp <= Utc::now().timestamp() {
        return Err(AuthError::ExpiredToken);
    }
    Ok(claims)
}

fn decode_secret(secret: &str) -> Result<Vec<u8>> {
    BASE64_STANDARD
        .decode(secret)
        .map_err(|e| AuthError::Base64Error(format!("Failed to decode JWT secret: {}", e)))
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;

    use super::*;

    #[test]
    fn test_create_validate_jwt() {
        let session_id = Uuid::new_v4();
        let secret_key = Secret::new(BASE64_STANDARD.encode("test-secret-key"));
        let jwt_config = JwtConfig {
            secret: secret_key,
            ttl: 3600,
        };
        let token = create_jwt(session_id, &jwt_config).unwrap();
        let claims = validate_token(&token, &jwt_config).unwrap();

        assert_eq!(claims.sub, session_id);
        assert!(claims.exp > Utc::now().timestamp());
    }

    #[test]
    fn test_jwt_wrong_secret() {
        let session_id = Uuid::new_v4();
        let secret_key = Secret::new(BASE64_STANDARD.encode("test-secret-key"));
        let jwt_config_correct = JwtConfig {
            secret: secret_key,
            ttl: 3600,
        };
        let token = create_jwt(session_id, &jwt_config_correct).unwrap();
        let jwt_config_incorrect = JwtConfig {
            secret: Secret::new(BASE64_STANDARD.encode("test-secret-wrong-key")),
            ttl: 3600,
        };
        let result = validate_token(&token, &jwt_config_incorrect);
        assert!(matches!(result, Err(AuthError::InvalidChallenge)));
    }

    #[test]
    fn test_expired_token() {
        let session_id = Uuid::new_v4();
        let secret_key = Secret::new(BASE64_STANDARD.encode("test-secret-key"));
        let config = JwtConfig {
            secret: secret_key,
            ttl: -2,
        }; // Already expired

        let token = create_jwt(session_id, &config).unwrap();
        let result = validate_token(&token, &config);
        assert!(matches!(result, Err(AuthError::ExpiredToken)));
    }
}
