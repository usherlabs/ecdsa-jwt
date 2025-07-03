use crate::{auth::PubKey, error::AuthError};
use base64::prelude::*;
use k256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    pkcs8::DecodePublicKey,
};
use simple_ecdsa_verifier::validate_ecdsa_signature;

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
pub fn verify_signature_pem(
    public_key: &str,
    challenge: &[u8],
    signature_der: &[u8],
) -> Result<(), AuthError> {
    let signature = Signature::from_der(signature_der)
        .map_err(|e| AuthError::CryptoError(format!("Failed to parse signature: {e}")))?;

    let verifying_key = VerifyingKey::from_public_key_pem(public_key)
        .map_err(|e| AuthError::InvalidPublicKey(format!("Failed to derive verifying key: {e}")))?;
    verifying_key
        .verify(challenge, &signature)
        .map_err(|e| AuthError::InvalidSignature(format!("Failed to verfiy: {e}")))
}

/// Verifies an Ethereum-style ECDSA signature against a 20-byte address.
///
/// Converts the DER-encoded signature to hex, the challenge to a UTF-8 string,
/// and validates that the signature recovers the provided public key address.
///
/// # Arguments
/// * `public_key` - A 0x-prefixed Ethereum address string (e.g. "0xabc...")
/// * `challenge` - Raw bytes of the challenge message (e.g. from server)
/// * `signature_der` - DER-encoded ECDSA signature as bytes
///
/// # Returns
/// * `Ok(())` if the signature is valid and recovers the address
/// * `Err(AuthError)` if the signature is invalid or recovery fails
pub fn verify_signature_eth(
    public_key: &str,
    challenge: &[u8],
    signature_der: &[u8],
) -> Result<(), AuthError> {
    let public_key = public_key.to_string();
    let signature_hex = hex::encode(signature_der);
    let message = String::from_utf8(challenge.to_vec()).unwrap();

    let signature_is_valid = validate_ecdsa_signature(&signature_hex, &message, &public_key)
        .map_err(|e| AuthError::CryptoError(e.to_string()))?;

    if !signature_is_valid {
        return Err(AuthError::InvalidSignature("invalid signature".into()));
    }

    Ok(())
}

/// Verifies a public key of unknown format (PEM or Ethereum) against a signature and challenge.
///
/// Internally detects the key type and dispatches to the appropriate verifier.
///
/// # Arguments
/// * `public_key` - Either a PEM-encoded public key or a 0x-prefixed Ethereum address
/// * `challenge` - Raw challenge bytes (must match what was signed)
/// * `signature_der` - DER-encoded ECDSA signature
///
/// # Returns
/// * `Ok(())` if the signature is valid for the public key
/// * `Err(AuthError)` if the key is invalid or the signature check fails
pub fn verify_signature(
    public_key: &str,
    challenge: &[u8],
    signature_der: &[u8],
) -> Result<(), AuthError> {
    let public_key: PubKey = public_key.to_string().try_into()?;
    let pub_key_str = public_key.to_string();

    match public_key {
        PubKey::EthAddress(_) => verify_signature_eth(&pub_key_str, challenge, signature_der),
        PubKey::Pem(_) => verify_signature_pem(&pub_key_str, challenge, signature_der),
    }
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
        .map_err(|e| AuthError::Base64Error(format!("Failed to decode challenge: {e}")))?;

    let signature_bytes = BASE64_STANDARD
        .decode(signature_b64)
        .map_err(|e| AuthError::Base64Error(format!("Failed to decode signature: {e}")))?;

    verify_signature_pem(public_key_pem, &challenge_bytes, &signature_bytes)
}

#[cfg(test)]
mod tests {

    use super::*;
    // This is a valid DER structure but not a real signature
    const VALID_DER_SIGNATURE: &[u8] = &[
        0x30, 0x44, 0x02, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
        0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x02, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
        0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f, 0x40,
    ];

    #[test]
    fn test_invalid_signature_format() {
        let key = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----";
        let challenge = b"test challenge";
        let invalid_signature = &[0xFF, 0xFF]; // Invalid DER

        let result = verify_signature_pem(key, challenge, invalid_signature);
        assert!(matches!(result, Err(AuthError::CryptoError(_))));
    }

    #[test]
    fn test_invalid_public_key() {
        let invalid_key = "not a valid PEM key";
        let challenge = b"test challenge";

        let result = verify_signature_pem(invalid_key, challenge, VALID_DER_SIGNATURE);
        assert!(matches!(result, Err(AuthError::InvalidPublicKey(_))));
    }

    // Tests for verify_signature_b64 function
    #[test]
    fn test_b64_invalid_challenge_base64() {
        let public_key_pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----";
        let invalid_challenge_b64 = "not-valid-base64";
        let signature_b64 = BASE64_STANDARD.encode(VALID_DER_SIGNATURE);

        let result = verify_signature_b64(public_key_pem, invalid_challenge_b64, &signature_b64);
        assert!(matches!(result, Err(AuthError::Base64Error(_))));
    }

    #[test]
    fn test_b64_invalid_signature_base64() {
        let public_key_pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----";
        let challenge_b64 = BASE64_STANDARD.encode(b"test challenge");
        let invalid_signature_b64 = "not-valid-base64";

        let result = verify_signature_b64(public_key_pem, &challenge_b64, invalid_signature_b64);
        assert!(matches!(result, Err(AuthError::Base64Error(_))));

        // Verify the error message mentions signature
        if let Err(AuthError::Base64Error(msg)) = result {
            assert!(msg.contains("signature"));
        }
    }

    // Tests for verify_signature_eth function
    #[test]
    fn test_valid_eth_signature_format() {
        let pub_key = "0xd1798d6b74ef965d6a60f45e0036f44aed3dfa1b";
        let challenge = b"4RvWUp3E9YerY78Kn5UyyEQPTiFs0tIr/mhAeCbwIpY=";
        let valid_signature = hex::decode("88bd1f104e132178aea55731be455a5c91b3e15b46f2599e9472d926270d458f4116eea0273fb5dc36238992154afc652aa7c1d91569b596db00146b4e5443fa1b").unwrap();

        let result = verify_signature_eth(pub_key, challenge, &valid_signature);
        assert!(matches!(result, Ok(())));
    }

    #[test]
    fn test_invalid_eth_public_key() {
        let pub_key = "0xd1798d6b74ef965d6a60f45e0036f44aed3dfa1b";
        let challenge = b"4RvWUp3E9YerY78Kn5UyyEQPTiFs0tIr/mhAeCbwIpY=";
        let invalid_signature = hex::decode("99bd1f104e132178aea55731be455a5c91b3e15b46f2599e9472d926270d458f4116eea0273fb5dc36238992154afc652aa7c1d91569b596db00146b4e5443fa1b").unwrap();

        let result = verify_signature_eth(pub_key, challenge, &invalid_signature);
        assert!(matches!(result, Err(AuthError::CryptoError(_))));
    }
}
