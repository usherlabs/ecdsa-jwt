use crate::{
    config::JwtConfig,
    crypto::{
        challenge::generate_challenge,
        ecdsa::verify_signature,
        jwt::{create_jwt, validate_token, Claims},
    },
    error::{AuthError, Result},
};
use base64::prelude::*;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Authentication service that handles ECDSA challenge-based authentication
///
/// This service provides stateless authentication operations:
/// - Challenge generation for clients to sign
/// - Signature verification against challenges
/// - JWT token creation for authenticated sessions
/// - JWT token validation
///
/// The service does not store any state - developers must handle challenge
/// storage and session management in their own systems.
pub struct AuthService {
    pub jwt_config: JwtConfig,
}

/// Request structure for authenticating with a signed challenge
///
/// This contains all the data needed to verify a client's identity:
/// - The original challenge that was provided to the client
/// - The client's signature of that challenge (proves private key ownership)
/// - The client's public key (used to verify the signature)
#[derive(Serialize, Deserialize)]
pub struct AuthRequest {
    pub challenge: String,
    pub signature: String,
    pub public_key_pem: String,
}

/// Response structure containing authentication results
///
/// Returned after successful signature verification, contains:
/// - A JWT token for subsequent API requests
/// - Session identifier for tracking
/// - Token expiration timestamp
#[derive(Serialize, Deserialize)]
pub struct AuthResponse {
    pub session_id: Uuid,
    pub session_token: String,
    pub expires_at: i64,
}

impl AuthService {
    /// Create a new authentication service with the given JWT configuration
    ///
    /// # Arguments
    /// * `jwt_config` - Configuration containing JWT secret and token lifetime
    ///
    /// # Example
    /// ```rust
    /// use ecdsa_jwt::{auth::{AuthService},config::JwtConfig};
    /// use secrecy::Secret;
    /// use base64::prelude::*;
    ///
    /// let config = JwtConfig {  
    ///     secret: Secret::new(BASE64_STANDARD.encode("your-secret")),
    ///     ttl: 3600, // 1 hour
    /// };
    /// let auth_service = AuthService::new(config);
    /// ```
    pub fn new(jwt_config: JwtConfig) -> Self {
        Self { jwt_config }
    }

    /// Generate a cryptographically secure random challenge
    ///
    /// Creates a 32-byte random challenge encoded as base64.
    /// This challenge should be:
    /// 1. Sent to the client
    /// 2. Stored temporarily by the server (with expiration)
    /// 3. Signed by the client using their private key
    /// 4. Submitted back with the signature for verification
    ///
    /// # Returns
    /// Base64-encoded 32-byte random challenge
    ///
    /// # Example
    /// ```rust
    /// use ecdsa_jwt::{auth::{AuthService},config::JwtConfig};
    /// use secrecy::Secret;
    /// use base64::prelude::*;
    ///
    /// let config = JwtConfig {  
    ///     secret: Secret::new(BASE64_STANDARD.encode("your-secret")),
    ///     ttl: 3600, // 1 hour
    /// };
    /// let auth_service = AuthService::new(config);
    /// let challenge = auth_service.generate_challenge();
    /// // Store this challenge with a session ID and expiration time
    /// // Send challenge to client for signing
    /// ```
    pub fn generate_challenge(&self) -> String {
        generate_challenge()
    }

    /// Authenticate a client by verifying their signed challenge
    ///
    /// This is the core authentication method that:
    /// 1. Validates all input parameters
    /// 2. Decodes base64-encoded challenge and signature
    /// 3. Verifies the ECDSA signature using the provided public key
    /// 4. Creates and returns a JWT token on successful verification
    ///
    /// # Arguments
    /// * `auth_request` - Contains challenge, signature, and public key
    ///
    /// # Returns
    /// * `Ok(AuthResponse)` - Authentication successful, contains JWT token
    /// * `Err(AuthError)` - Authentication failed with specific error details
    ///
    /// # Errors
    /// - `InvalidPublicKey` - Public key is empty or malformed
    /// - `InvalidChallenge` - Challenge is empty or invalid
    /// - `InvalidSignature` - Signature is empty, malformed, or verification failed
    /// - `Base64Error` - Challenge or signature has invalid base64 encoding
    /// - `CryptoError` - Unexpected cryptographic operation failure
    ///
    /// # Example
    /// ```rust
    /// use ecdsa_jwt::{auth::{AuthService, AuthRequest},config::JwtConfig};
    /// use secrecy::Secret;
    /// use base64::prelude::*;
    ///
    /// let config = JwtConfig {  
    ///     secret: Secret::new(BASE64_STANDARD.encode("your-secret")),
    ///     ttl: 3600, // 1 hour
    /// };
    ///
    /// let auth_request = AuthRequest {
    ///     challenge: "stored_challenge".to_string(),
    ///     signature: "client_signature".to_string(),
    ///     public_key_pem: "client_public_key".to_string(),
    /// };
    /// let auth_service = AuthService::new(config);
    /// match auth_service.authenticate(auth_request) {
    ///     Ok(response) => {
    ///         println!("Authentication successful!");
    ///         println!("JWT: {}", response.session_token);
    ///     }
    ///     Err(e) => println!("Authentication failed: {}", e),
    /// }
    /// ```
    pub fn authenticate(&self, auth_request: AuthRequest) -> Result<AuthResponse> {
        if auth_request.public_key_pem.trim().is_empty() {
            return Err(AuthError::InvalidPublicKey(
                "Invalid Public Key".to_string(),
            ));
        }
        if auth_request.challenge.trim().is_empty() {
            return Err(AuthError::InvalidChallenge);
        }
        if auth_request.signature.trim().is_empty() {
            return Err(AuthError::InvalidSignature("Invalid Signature".to_string()));
        }

        let challenge_bytes = base64::prelude::BASE64_STANDARD
            .decode(&auth_request.challenge)
            .map_err(|e| AuthError::Base64Error(format!("Invalid challenge encoding: {}", e)))?;

        let signature_bytes = base64::prelude::BASE64_STANDARD
            .decode(&auth_request.signature)
            .map_err(|e| AuthError::Base64Error(format!("Invalid signature encoding: {}", e)))?;

        match verify_signature(
            &auth_request.public_key_pem,
            &challenge_bytes,
            &signature_bytes,
        ) {
            Ok(()) => self.create_jwt_response(),
            Err(AuthError::CryptoError(msg)) => {
                // handle signature error
                Err(AuthError::InvalidSignature(format!(
                    "Invalid signature format: {}",
                    msg
                )))
            }
            Err(AuthError::InvalidPublicKey(msg)) => {
                // Handle public key errors
                Err(AuthError::InvalidPublicKey(format!(
                    "Invalid public key format: {}",
                    msg
                )))
            }
            Err(AuthError::InvalidSignature(msg)) => {
                // Handle verification failures
                Err(AuthError::InvalidSignature(format!(
                    "Signature verification failed: {}",
                    msg
                )))
            }
            Err(other_error) => {
                //  Handle unexpected errors
                Err(AuthError::CryptoError(format!(
                    "Unexpected verification error: {}",
                    other_error
                )))
            }
        }
    }

    /// Create JWT response after successful signature verification
    ///
    /// This private method is called only after signature verification succeeds.
    /// It generates a new session ID and creates a JWT token with the configured
    /// secret and expiration time.
    ///
    /// # Returns
    /// * `Ok(AuthResponse)` - JWT token created successfully
    /// * `Err(AuthError)` - JWT creation failed
    fn create_jwt_response(&self) -> Result<AuthResponse> {
        let session_id = Uuid::new_v4();

        let jwt_token = create_jwt(session_id, &self.jwt_config)?;

        let expires_at = chrono::Utc::now().timestamp() + self.jwt_config.ttl;

        Ok(AuthResponse {
            session_token: jwt_token,
            session_id,
            expires_at,
        })
    }

    /// Validate a JWT session token
    ///
    /// Verifies that a JWT token is:
    /// - Properly formatted
    /// - Signed with the correct secret
    /// - Not expired
    /// - Contains valid claims
    ///
    /// # Arguments
    /// * `token` - JWT token string to validate
    ///
    /// # Returns
    /// * `Ok(Claims)` - Token is valid, returns parsed claims
    /// * `Err(AuthError)` - Token is invalid, expired, or malformed
    ///
    /// # Example
    /// ```rust
    /// use ecdsa_jwt::{auth::{AuthService, AuthRequest},config::JwtConfig};
    /// use secrecy::Secret;
    /// use base64::prelude::*;
    ///
    /// let config = JwtConfig {  
    ///     secret: Secret::new(BASE64_STANDARD.encode("your-secret")),
    ///     ttl: 3600, // 1 hour
    /// };
    ///
    /// let auth_service = AuthService::new(config);
    /// let jwt_token = "token";
    /// match auth_service.validate_session(&jwt_token) {
    ///     Ok(claims) => {
    ///         println!("Valid session for user: {}", claims.sub);
    ///         // Allow access to protected resource
    ///     }
    ///     Err(_) => {
    ///         println!("Invalid token - access denied");
    ///         // Return 401 Unauthorized
    ///     }
    /// }
    /// ```
    pub fn validate_session(&self, token: &str) -> Result<Claims> {
        if token.trim().is_empty() {
            return Err(AuthError::InvalidToken);
        }
        validate_token(token, &self.jwt_config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::JwtConfig;
    use secrecy::Secret;

    fn create_test_auth_service() -> AuthService {
        let jwt_config = JwtConfig {
            secret: Secret::new(BASE64_STANDARD.encode("test-secret-key")),
            ttl: 3600,
        };
        AuthService::new(jwt_config)
    }

    #[test]
    fn test_generate_challenge() {
        let auth_service = create_test_auth_service();
        let challenge = auth_service.generate_challenge();
        assert!(!challenge.is_empty());

        // Should be base64 encoded 32 bytes
        let decoded = BASE64_STANDARD.decode(&challenge).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_authenticate_with_empty_challenge() {
        let auth_service = create_test_auth_service();

        let auth_request = AuthRequest {
            challenge: "".to_string(),
            signature: BASE64_STANDARD.encode([0u8; 64]),
            public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
                .to_string(),
        };

        let result = auth_service.authenticate(auth_request);
        assert!(matches!(result, Err(AuthError::InvalidChallenge)));
    }

    #[test]
    fn test_authenticate_with_empty_signature() {
        let auth_service = create_test_auth_service();

        let auth_request = AuthRequest {
            challenge: BASE64_STANDARD.encode([0u8; 32]),
            signature: "".to_string(),
            public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
                .to_string(),
        };

        let result = auth_service.authenticate(auth_request);
        assert!(matches!(result, Err(AuthError::InvalidSignature(_))));
    }

    #[test]
    fn test_authenticate_with_empty_public_key() {
        let auth_service = create_test_auth_service();

        let auth_request = AuthRequest {
            challenge: BASE64_STANDARD.encode([0u8; 32]),
            signature: BASE64_STANDARD.encode([0u8; 64]),
            public_key_pem: "".to_string(),
        };

        let result = auth_service.authenticate(auth_request);
        assert!(matches!(result, Err(AuthError::InvalidPublicKey(_))));
    }
    #[test]
    fn test_authenticate_with_invalid_challenge_length() {
        let auth_service = create_test_auth_service();

        let auth_request = AuthRequest {
            challenge: BASE64_STANDARD.encode([0u8; 16]), // Wrong length
            signature: BASE64_STANDARD.encode([0u8; 64]),
            public_key_pem: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----"
                .to_string(),
        };

        let result = auth_service.authenticate(auth_request);
        assert!(matches!(result, Err(AuthError::InvalidSignature(_))));
    }

    #[test]
    fn test_validate_session() {
        let auth_service = create_test_auth_service();
        let session_id = Uuid::new_v4();

        // Create a JWT manually for testing
        let token = crate::crypto::jwt::create_jwt(session_id, &auth_service.jwt_config).unwrap();

        let claims = auth_service.validate_session(&token).unwrap();
        assert_eq!(claims.sub, session_id);
    }
}
