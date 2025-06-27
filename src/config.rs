use secrecy::Secret;
use serde::Deserialize;

/// Configuration for JWT token creation and validation
///
/// This struct contains the settings needed for JWT operations:
/// - A secret key for signing and verifying tokens
/// - Token lifetime (TTL) in seconds
///
/// # Security Note
/// The secret should be a strong, randomly generated key. For production use,
/// generate at least 256 bits of random data and encode it as base64.
///
/// # Example
/// ```rust
/// use ecdsa_jwt::JwtConfig;
/// use secrecy::Secret;
/// use base64::prelude::*;
///
/// let config = JwtConfig {
///     secret: Secret::new(BASE64_STANDARD.encode("your-256-bit-secret-key")),
///     ttl: 3600, // 1 hour
/// };
/// ```
#[derive(Clone, Debug, Deserialize)]
pub struct JwtConfig {
    /// JWT secret key, base64 encoded string
    /// 
    /// This secret is used to sign and verify JWT tokens. It should be:
    /// - At least 256 bits (32 bytes) of random data
    /// - Base64 encoded
    /// - Kept secure and not committed to version control
    pub secret: Secret<String>,
    /// JWT Time To Live (TTL) in seconds
    /// 
    /// This determines how long JWT tokens remain valid after creation.
    /// Common values:
    /// - 3600 (1 hour) for most applications
    /// - 86400 (24 hours) for longer sessions
    /// - 300 (5 minutes) for short-lived tokens
    pub ttl: i64,
}
