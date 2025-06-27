use std::fmt;

/// Authentication and cryptographic operation errors
///
/// This enum provides detailed error information for debugging authentication
/// and cryptographic operations. Each variant includes context about what went wrong.
///
/// # Example
/// ```rust
/// use ecdsa_jwt::{AuthError, Result};
///
/// fn handle_auth_result(result: Result<()>) {
///     match result {
///         Ok(()) => println!("Operation successful"),
///         Err(AuthError::InvalidSignature(msg)) => println!("Signature error: {}", msg),
///         Err(AuthError::ExpiredToken) => println!("Token has expired"),
///         Err(e) => println!("Other error: {}", e),
///     }
/// }
/// ```
#[derive(Debug)]
pub enum AuthError {
    /// ECDSA signature verification failed
    ///
    /// This error occurs when:
    /// - The signature format is invalid
    /// - The signature doesn't match the challenge and public key
    /// - The public key is incompatible with the signature
    InvalidSignature(String),

    /// Public key format is invalid or cannot be parsed
    ///
    /// This error occurs when:
    /// - The PEM format is malformed
    /// - The key is not a valid ECDSA public key
    /// - The key uses an unsupported curve
    InvalidPublicKey(String),

    /// JWT token is invalid, malformed, or has wrong signature
    ///
    /// This error occurs when:
    /// - The JWT format is invalid
    /// - The token signature doesn't match the secret
    /// - The token structure is malformed
    InvalidToken,

    /// Token has expired
    ///
    /// This error occurs when the JWT's expiration timestamp
    /// is in the past relative to the current time.
    ExpiredToken,

    /// Challenge has expired
    ///
    /// This error occurs when a challenge is used after its
    /// configured expiration time.
    ExpiredChallenge,

    /// Challenge format is invalid
    ///
    /// This error occurs when:
    /// - The challenge is empty
    /// - The challenge is not base64 encoded
    /// - The challenge has the wrong length
    InvalidChallenge,

    /// Base64 decoding failed
    ///
    /// This error occurs when:
    /// - The input contains invalid base64 characters
    /// - The input length is not valid for base64
    /// - Padding is incorrect
    Base64Error(String),

    /// JWT creation or parsing error
    ///
    /// This error occurs when:
    /// - JWT encoding/decoding fails
    /// - The secret is invalid
    /// - The claims structure is incompatible
    JwtError(String),

    /// Generic cryptographic operation error
    ///
    /// This error occurs for unexpected cryptographic failures
    /// that don't fit into other categories.
    CryptoError(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::InvalidSignature(msg) => {
                write!(f, "ECDSA signature verification failed: {msg}")
            }
            AuthError::InvalidPublicKey(msg) => {
                write!(f, "Invalid public key: {msg}")
            }
            AuthError::InvalidToken => {
                write!(f, "Invalid or malformed JWT token")
            }
            AuthError::ExpiredToken => {
                write!(f, "Token has expired")
            }
            AuthError::ExpiredChallenge => {
                write!(f, "Challenge has expired")
            }
            AuthError::InvalidChallenge => {
                write!(f, "Invalid challenge format")
            }
            AuthError::Base64Error(msg) => {
                write!(f, "Base64 decode error: {msg}")
            }
            AuthError::JwtError(msg) => {
                write!(f, "JWT error: {msg}")
            }
            AuthError::CryptoError(msg) => {
                write!(f, "Cryptographic error: {msg}")
            }
        }
    }
}

impl std::error::Error for AuthError {}

pub type Result<T> = std::result::Result<T, AuthError>;
