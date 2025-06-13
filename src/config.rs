use secrecy::Secret;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct JwtConfig {
    /// JWT secret, base64 encoded string
    pub secret: Secret<String>,
    /// JWT Time To Live (in seconds)
    pub ttl: i64,
}
