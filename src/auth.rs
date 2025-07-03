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
///
/// # Example
/// ```rust
/// use ecdsa_jwt::{AuthService, JwtConfig};
/// use secrecy::Secret;
/// use base64::prelude::*;
///
/// let config = JwtConfig {
///     secret: Secret::new(BASE64_STANDARD.encode("your-secret")),
///     ttl: 3600, // 1 hour
/// };
/// let auth_service = AuthService::new(config);
/// ```
pub struct AuthService {
    pub jwt_config: JwtConfig,
}

/// Request structure for authenticating with a signed challenge
///
/// This contains all the data needed to verify a client's identity:
/// - The original challenge that was provided to the client
/// - The client's signature of that challenge (proves private key ownership)
/// - The client's public key (used to verify the signature)
///
/// # Example
/// ```rust
/// use ecdsa_jwt::AuthRequest;
///
/// let auth_request = AuthRequest {
///     challenge: "base64-encoded-challenge".to_string(),
///     signature: "base64-encoded-signature".to_string(),
///     public_key: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string(),
/// };
/// ```
#[derive(Serialize, Deserialize)]
pub struct AuthRequest {
    /// Base64-encoded challenge that was signed by the client
    pub challenge: String,
    /// Base64-encoded ECDSA signature of the challenge
    pub signature: String,
    /// PEM-encoded public key used to verify the signature
    pub public_key: String,
}

/// Represents a public key in one of two supported formats.
#[derive(Serialize, Deserialize)]
pub enum PubKey {
    /// A PEM-encoded public key string (commonly used for ECDSA or RSA).
    Pem(String),

    /// A 20-byte Ethereum-style public key hash or address.
    /// This is not a compressed public key — it is the Keccak256 hash of a public key (last 20 bytes).
    EthAddress([u8; 20]),
}

impl ToString for PubKey {
    fn to_string(&self) -> String {
        match self {
            PubKey::Pem(s) => s.clone(),
            PubKey::EthAddress(bytes) => format!("0x{}", hex::encode(bytes)),
        }
    }
}

impl TryFrom<String> for PubKey {
    type Error = AuthError;
    fn try_from(s: String) -> std::result::Result<Self, Self::Error> {
        match s {
            // condition for ethereum address as public key
            s if s.starts_with("0x") && s.len() == 42 => {
                // remove the 0x and convert to a vector
                let bytes = hex::decode(&s[2..])
                    .map_err(|e| AuthError::InvalidSignature(format!("Invalid hex: {}", e)))?;
                // convert from vec to u8
                let bytes: [u8; 20] = bytes.try_into().map_err(|_| {
                    AuthError::InvalidPublicKey("Expected 20-byte address".to_string())
                })?;
                // return the instance of the enum
                Ok(PubKey::EthAddress(bytes))
            }

            // condition for PEM file as public key
            s if s.contains("-----BEGIN PUBLIC KEY-----") => Ok(PubKey::Pem(s.to_string())),

            _ => Err(AuthError::InvalidPublicKey(
                "Unsupported public key format".into(),
            )),
        }
    }
}

/// Response structure containing authentication results
///
/// Returned after successful signature verification, contains:
/// - A JWT token for subsequent API requests
/// - Session identifier for tracking
/// - Token expiration timestamp
///
/// # Example
/// ```rust
/// use ecdsa_jwt::AuthResponse;
///
/// let response = AuthResponse {
///     session_id: uuid::Uuid::new_v4(),
///     session_token: "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...".to_string(),
///     expires_at: 1640995200,
/// };
/// ```
#[derive(Serialize, Deserialize)]
pub struct AuthResponse {
    /// Unique session identifier
    pub session_id: Uuid,
    /// JWT token for subsequent API requests
    pub session_token: String,
    /// Unix timestamp when the token expires
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
    ///     public_key: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string(),
    /// };
    /// let auth_service = AuthService::new(config);
    /// match auth_service.authenticate(auth_request, true) { // true = include public key in JWT
    ///     Ok(response) => {
    ///         println!("Authentication successful!");
    ///         println!("JWT: {}", response.session_token);
    ///     }
    ///     Err(e) => println!("Authentication failed: {}", e),
    /// }
    /// ```
    pub fn authenticate(
        &self,
        auth_request: AuthRequest,
        include_public_key: bool,
    ) -> Result<AuthResponse> {
        let pub_key = auth_request.public_key;

        if auth_request.challenge.trim().is_empty() {
            return Err(AuthError::InvalidChallenge);
        }
        if auth_request.signature.trim().is_empty() {
            return Err(AuthError::InvalidSignature("Invalid Signature".to_string()));
        }

        let challenge_bytes = BASE64_STANDARD
            .decode(&auth_request.challenge)
            .map_err(|e| AuthError::Base64Error(format!("Invalid challenge encoding: {e}")))?;
        let signature_bytes = BASE64_STANDARD
            .decode(&auth_request.signature)
            .map_err(|e| AuthError::Base64Error(format!("Invalid signature encoding: {e}")))?;

        match verify_signature(&pub_key.to_string(), &challenge_bytes, &signature_bytes) {
            Ok(()) => self.create_jwt_response(if include_public_key {
                Some(pub_key.to_string())
            } else {
                None
            }),
            Err(AuthError::InvalidSignature(msg)) => Err(AuthError::InvalidSignature(format!(
                "Invalid signature format: {msg}"
            ))),
            Err(AuthError::InvalidPublicKey(msg)) => Err(AuthError::InvalidPublicKey(format!(
                "Invalid public key format: {msg}"
            ))),
            Err(AuthError::CryptoError(msg)) => Err(AuthError::InvalidSignature(format!(
                "Signature verification failed: {msg}"
            ))),
            Err(other_error) => Err(AuthError::CryptoError(format!(
                "Unexpected verification error: {other_error}"
            ))),
        }
    }

    /// Create JWT response after successful signature verification
    ///
    /// This private method is called only after signature verification succeeds.
    /// It generates a new session ID and creates a JWT token with the configured
    /// secret and expiration time.
    ///
    /// # Arguments
    /// * `public_key_pem` - Optional PEM-encoded public key used for authentication
    ///
    /// # Returns
    /// * `Ok(AuthResponse)` - JWT token created successfully
    /// * `Err(AuthError)` - JWT creation failed
    fn create_jwt_response(&self, public_key_pem: Option<String>) -> Result<AuthResponse> {
        let session_id = Uuid::new_v4();

        let jwt_token = create_jwt(session_id, public_key_pem, &self.jwt_config)?;

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

    /// Verify a signature using the public key from JWT claims
    ///
    /// This method extracts the public key from the JWT and uses it to verify
    /// a signature, eliminating the need to pass the public key separately.
    ///
    /// # Arguments
    /// * `jwt_token` - JWT token containing public key information
    /// * `challenge` - Challenge bytes that were signed
    /// * `signature` - Signature bytes to verify
    ///
    /// # Returns
    /// * `Ok(())` if signature is valid
    /// * `Err(AuthError)` if verification fails
    ///
    /// # Example
    /// ```rust
    /// use ecdsa_jwt::auth::AuthService;
    /// use ecdsa_jwt::config::JwtConfig;
    /// use secrecy::Secret;
    /// use base64::prelude::*;
    ///
    /// let jwt_config = JwtConfig {
    ///     secret: Secret::new(BASE64_STANDARD.encode("test-secret")),
    ///     ttl: 3600,
    /// };
    /// let auth_service = AuthService::new(jwt_config);
    ///
    /// // This would normally be a real JWT token with embedded public key
    /// let jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...";
    /// let challenge = b"challenge bytes";
    /// let signature = &[0x30, 0x44, 0x02, 0x20]; // Example DER signature
    ///
    /// // Note: This will fail with a real JWT that doesn't contain a public key
    /// // This is just demonstrating the API usage
    /// let _result = auth_service.verify_signature_from_jwt(jwt_token, challenge, signature);
    /// ```
    pub fn verify_signature_from_jwt(
        &self,
        jwt_token: &str,
        challenge: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        crate::crypto::jwt::verify_signature_from_jwt(
            jwt_token,
            &self.jwt_config,
            challenge,
            signature,
        )
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
            public_key: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----".to_string(),
        };

        let result = auth_service.authenticate(auth_request, true);
        assert!(matches!(result, Err(AuthError::InvalidChallenge)));
    }

    #[test]
    fn test_authenticate_with_empty_signature() {
        let auth_service = create_test_auth_service();

        let auth_request = AuthRequest {
            challenge: BASE64_STANDARD.encode([0u8; 32]),
            signature: "".to_string(),
            public_key: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----".to_string(),
        };

        let result = auth_service.authenticate(auth_request, true);
        assert!(matches!(result, Err(AuthError::InvalidSignature(_))));
    }

    #[test]
    fn test_authenticate_with_empty_public_key() {
        let auth_service = create_test_auth_service();

        let auth_request = AuthRequest {
            challenge: BASE64_STANDARD.encode([0u8; 32]),
            signature: BASE64_STANDARD.encode([0u8; 64]),
            public_key: "".to_string(),
        };

        let result = auth_service.authenticate(auth_request, true);
        assert!(matches!(result, Err(AuthError::InvalidPublicKey(_))));
    }
    #[test]
    fn test_authenticate_with_invalid_challenge_length() {
        let auth_service = create_test_auth_service();

        let auth_request = AuthRequest {
            challenge: BASE64_STANDARD.encode([0u8; 16]), // Wrong length
            signature: BASE64_STANDARD.encode([0u8; 64]),
            public_key: "-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----".to_string(),
        };

        let result = auth_service.authenticate(auth_request, true);
        assert!(matches!(result, Err(AuthError::InvalidSignature(_))));
    }

    #[test]
    fn test_validate_session() {
        let auth_service = create_test_auth_service();
        let session_id = Uuid::new_v4();

        // Create a JWT manually for testing
        let public_key = Some("-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----".to_string());
        let token =
            crate::crypto::jwt::create_jwt(session_id, public_key, &auth_service.jwt_config)
                .unwrap();

        let claims = auth_service.validate_session(&token).unwrap();
        assert_eq!(claims.sub, session_id);
    }
}
