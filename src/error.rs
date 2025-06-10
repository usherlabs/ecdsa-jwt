use std::fmt;

#[derive(Debug)]
pub enum AuthError {
    /// ECDSA signature verification failed
    InvalidSignature(String),

    /// Public key format is invalid or cannot be parsed
    InvalidPublicKey(String),

    /// JWT token is invalid, malformed, or has wrong signature
    InvalidToken,

    /// Challenge or token has expired
    ExpiredChallenge,

    /// Challenge format is invalid
    InvalidChallenge,

    /// Base64 decoding failed
    Base64Error(String),

    /// JWT creation or parsing error
    JwtError(String),

    /// Generic cryptographic operation error
    CryptoError(String),
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthError::InvalidSignature(msg) => {
                write!(f, "ECDSA signature verification failed: {}", msg)
            }
            AuthError::InvalidPublicKey(msg) => {
                write!(f, "Invalid public key: {}", msg)
            }
            AuthError::InvalidToken => {
                write!(f, "Invalid or malformed JWT token")
            }
            AuthError::ExpiredChallenge => {
                write!(f, "Challenge or token has expired")
            }
            AuthError::InvalidChallenge => {
                write!(f, "Invalid challenge format")
            }
            AuthError::Base64Error(msg) => {
                write!(f, "Base64 decode error: {}", msg)
            }
            AuthError::JwtError(msg) => {
                write!(f, "JWT error: {}", msg)
            }
            AuthError::CryptoError(msg) => {
                write!(f, "Cryptographic error: {}", msg)
            }
        }
    }
}

impl std::error::Error for AuthError {}

pub type Result<T> = std::result::Result<T, AuthError>;
