use crate::error::AuthError;
use base64::prelude::*;
use k256::{
    ecdsa::{Signature, VerifyingKey, signature::Verifier},
    pkcs8::DecodePublicKey,
};

/// Verify an ECDSA signature against a challenge using a public key
///
/// # Arguments
/// * `public_key_pem` - PEM-encoded public key string
/// * `challenge` - Raw challenge bytes that were signed
/// * `signature_der` - DER-encoded signature bytes
///
/// # Returns
/// * `Ok(())` if signature is valid
/// * `Err(AuthError)` if verification fails
///
/// # Example
/// ```rust
/// use ecdsa_jwt::crypto::verify_signature;
///
/// let public_key_pem = "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----";
/// let challenge = b"random challenge bytes";
/// let signature = &[0x30, 0x44, 0x02, 0x20]; // DER-encoded signature
///
/// match verify_signature(public_key_pem, challenge, signature) {
///     Ok(()) => println!("Signature is valid!"),
///     Err(e) => println!("Verification failed: {}", e),
/// }
/// ```
pub fn verify_signature(
    public_key_pem: &str,
    challenge: &[u8],
    signature_der: &[u8],
) -> Result<(), AuthError> {
    let signature = Signature::from_der(signature_der)
        .map_err(|e| AuthError::CryptoError(format!("Failed to parse signature: {}", e)))?;

    let verifying_key = VerifyingKey::from_public_key_pem(public_key_pem).map_err(|e| {
        AuthError::InvalidPublicKey(format!("Failed to derive verifying key: {}", e))
    })?;
    verifying_key
        .verify(challenge, &signature)
        .map_err(|e| AuthError::InvalidSignature(format!("Failed to verfiy: {}", e)))
}

/// Verify an ECDSA signature with base64-encoded inputs (convenience function)
/// This is a wrapper around `verify_signature` that handles base64 decoding
///
/// # Arguments  
/// * `public_key_pem` - PEM-encoded public key string
/// * `challenge_b64` - Base64-encoded challenge bytes
/// * `signature_b64` - Base64-encoded DER signature
pub fn verify_signature_b64(
    public_key_pem: &str,
    challenge_b64: &str,
    signature_b64: &str,
) -> Result<(), AuthError> {
    let challenge_bytes = BASE64_STANDARD
        .decode(challenge_b64)
        .map_err(|e| AuthError::Base64Error(format!("Failed to decode challenge: {}", e)))?;

    let signature_bytes = BASE64_STANDARD
        .decode(signature_b64)
        .map_err(|e| AuthError::Base64Error(format!("Failed to decode signature: {}", e)))?;

    verify_signature(public_key_pem, &challenge_bytes, &signature_bytes)
}
