use crate::error::{AuthError, Result};
use base64::prelude::*;
use rand::Rng;

/// Generate a cryptographically secure random challenge
///
/// Returns 32 random bytes as base64 encoded string
///
/// # Example
/// ```rust
/// use ecdsa_jwt::crypto::challenge::generate_challenge;
///
/// let challenge = generate_challenge();
/// println!("Challenge: {}", challenge);
/// ```
pub fn generate_challenge() -> String {
    let mut rng = rand::thread_rng();
    let challenge_bytes: [u8; 32] = rng.r#gen();
    BASE64_STANDARD.encode(challenge_bytes)
}

/// Decode a base64 challenge string to bytes for verification
///
/// # Arguments
/// * `challenge_b64` - Base64 encoded challenge string
///
/// # Returns
/// * `Ok(Vec<u8>)` - Challenge bytes
/// * `Err(AuthError)` - If base64 decoding fails
///
/// # Example
/// ```rust
/// use ecdsa_jwt::crypto::challenge::{generate_challenge, decode_challenge};
///
/// let challenge = generate_challenge();
/// let challenge_bytes = decode_challenge(&challenge).unwrap();
/// assert_eq!(challenge_bytes.len(), 32);
/// ```
pub fn decode_challenge(challenge_b64: &str) -> Result<Vec<u8>> {
    BASE64_STANDARD
        .decode(challenge_b64)
        .map_err(|e| AuthError::Base64Error(format!("Failed to decode challenge: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_challenge() {
        let challenge1 = generate_challenge();
        let challenge2 = generate_challenge();

        // Should be different
        assert_ne!(challenge1, challenge2);

        // Should be base64 encoded 32 bytes
        let decoded = BASE64_STANDARD.decode(&challenge1).unwrap();
        assert_eq!(decoded.len(), 32);
    }

    #[test]
    fn test_decode_challenge() {
        let challenge = generate_challenge();
        let decoded = decode_challenge(&challenge).unwrap();

        assert_eq!(decoded.len(), 32);

        // Re-encode should match
        let re_encoded = BASE64_STANDARD.encode(&decoded);
        assert_eq!(re_encoded, challenge);
    }

    #[test]
    fn test_decode_invalid_challenge() {
        let result = decode_challenge("invalid-base64!");
        assert!(matches!(result, Err(AuthError::Base64Error(_))));
    }
}
