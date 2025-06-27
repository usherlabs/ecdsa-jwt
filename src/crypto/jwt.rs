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
use sha2::{Sha256, Digest};
use hex;

/// JWT claims structure for authenticated sessions
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Claims {
    /// User identifier/session ID
    pub sub: Uuid,
    /// Expiration timestamp (Unix timestamp)
    pub exp: i64,
    /// Issued at timestamp (Unix timestamp)
    pub iat: i64,
    /// Public key hash (SHA256 of the public key used for authentication)
    pub key_hash: Option<String>,
    /// Full public key PEM (for signature verification)
    pub public_key_pem: Option<String>,
}

/// Creates a signed JWT token for an authenticated session
///
/// # Arguments
/// * `session_id` - Unique session identifier
/// * `public_key_pem` - Optional PEM-encoded public key used for authentication
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
/// 
/// // Create JWT with public key
/// let public_key = Some("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----".to_string());
/// let token_with_key = create_jwt(session_id, public_key, &config).unwrap();
/// 
/// // Create JWT without public key
/// let token_without_key = create_jwt(session_id, None, &config).unwrap();
/// ```
pub fn create_jwt(session_id: Uuid, public_key_pem: Option<String>, config: &JwtConfig) -> Result<String> {
    let jwt_secret = decode_secret(config.secret.expose_secret())?;
    let now = Utc::now().timestamp();

    // Create hash of the public key if provided
    let (key_hash, public_key_pem_value) = if let Some(ref pk) = public_key_pem {
        let hash = create_public_key_hash(pk)?;
        (Some(hash), Some(pk.clone()))
    } else {
        (None, None)
    };

    let claims = Claims {
        sub: session_id,
        exp: now + config.ttl,
        iat: now,
        key_hash,
        public_key_pem: public_key_pem_value,
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

/// Create a hash of the public key for storage in JWT claims
fn create_public_key_hash(public_key_pem: &str) -> Result<String> {
    // Remove PEM headers and whitespace for consistent hashing
    let clean_key = public_key_pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");

    let mut hasher = Sha256::new();
    hasher.update(clean_key.as_bytes());
    let result = hasher.finalize();

    Ok(hex::encode(result))
}

/// Verify a signature using the public key from JWT claims
///
/// # Arguments
/// * `token` - JWT token containing public key information
/// * `config` - JWT configuration
/// * `challenge` - Challenge bytes that were signed
/// * `signature` - Signature bytes to verify
///
/// # Returns
/// * `Ok(())` if signature is valid
/// * `Err(AuthError)` if verification fails
///
/// # Example
/// ```rust
/// use ecdsa_jwt::crypto::jwt::verify_signature_from_jwt;
/// use ecdsa_jwt::config::JwtConfig;
/// use secrecy::Secret;
/// use base64::prelude::*;
///
/// let config = JwtConfig {
///     secret: Secret::new(BASE64_STANDARD.encode("test-secret")),
///     ttl: 3600,
/// };
/// let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...";
/// let challenge = b"challenge bytes";
/// let signature = &[0x30, 0x44, 0x02, 0x20]; // DER signature
///
/// // Note: This will fail with a real JWT that doesn't contain a public key
/// // This is just demonstrating the API usage
/// let _result = verify_signature_from_jwt(token, &config, challenge, signature);
/// ```
pub fn verify_signature_from_jwt(
    token: &str,
    config: &JwtConfig,
    challenge: &[u8],
    signature: &[u8],
) -> Result<()> {
    let claims = validate_token(token, config)?;
    
    // Use the public key from JWT if available
    let public_key_pem = claims.public_key_pem.ok_or_else(|| {
        AuthError::InvalidPublicKey("Public key not included in JWT".to_string())
    })?;
    
    // Verify the signature using the public key from JWT
    crate::crypto::ecdsa::verify_signature(&public_key_pem, challenge, signature)
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
        let token = create_jwt(session_id, Some("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string()), &jwt_config).unwrap();
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
        let token = create_jwt(session_id, Some("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string()), &jwt_config_correct).unwrap();
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

        let token = create_jwt(session_id, Some("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string()), &config).unwrap();
        let result = validate_token(&token, &config);
        assert!(matches!(result, Err(AuthError::ExpiredToken)));
    }
}
