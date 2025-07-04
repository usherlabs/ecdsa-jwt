use std::error::Error;

use easy_hasher::easy_hasher;

type DynamicResult<T> = Result<T, Box<dyn Error>>;

/// Validates an ECDSA signature against a given public Ethereum address.
///
/// # Arguments
/// * `public_key` - A `0x`-prefixed Ethereum address string (e.g., "0xabc...")
/// * `message` - The original message bytes that were signed
/// * `signature_hex` - A 65-byte ECDSA signature in raw binary format (r, s, v)
///
/// # Returns
/// * `Ok(true)` if the signature is valid and matches the address  
/// * `Ok(false)` if the signature does not match the address  
/// * `Err` if parsing or recovery fails
pub fn validate_ecdsa_signature(
    public_key: &str,
    message: &[u8],
    signature_hex: &[u8],
) -> DynamicResult<bool> {
    // Strip "0x" prefix for consistency
    let public_key_hex = public_key.replace("0x", "");

    // Recover address from signature + message
    let recovered_key = recover_address_from_eth_signature(signature_hex, message)?;
    let recovered_key_hex = hex::encode(recovered_key);

    // Compare lowercase versions for address match
    Ok(recovered_key_hex.to_lowercase() == public_key_hex.to_lowercase())
}

/// Recovers an Ethereum address from a raw ECDSA signature and original message.
///
/// # Arguments
/// * `metamask_signature` - A 65-byte ECDSA signature (r, s, v)
/// * `message` - The original signed message
///
/// # Returns
/// * `Ok(Vec<u8>)` - The recovered 20-byte Ethereum address
/// * `Err` - On decoding or recovery failure
fn recover_address_from_eth_signature(
    metamask_signature: &[u8],
    message: &[u8],
) -> DynamicResult<Vec<u8>> {
    // First 64 bytes are the signature
    let signature_bytes: [u8; 64] = metamask_signature[0..64].try_into()?;
    let signature_bytes_64 = libsecp256k1::Signature::parse_standard(&signature_bytes)?;

    // Final byte is the recovery ID
    let recovery_id = metamask_signature[64];
    let recovery_id_byte = libsecp256k1::RecoveryId::parse_rpc(recovery_id)?;

    // Hash the message using Ethereum's prefixed method
    let message_bytes: [u8; 32] = hash_eth_message(message)
        .try_into()
        .map_err(|e| format!("{:?}", e))?;
    let message_bytes_32 = libsecp256k1::Message::parse(&message_bytes);

    // Recover the public key using secp256k1 recovery
    let public_key =
        libsecp256k1::recover(&message_bytes_32, &signature_bytes_64, &recovery_id_byte)?;

    // Convert the recovered public key to an Ethereum address
    get_address_from_public_key(
        public_key
            .serialize_compressed()
            .to_vec()
            .try_into()
            .map_err(|e| format!("{:?}", e))?,
    )
}

/// Hashes a message using Ethereum's signed message prefix scheme.
///
/// # Arguments
/// * `message` - The original message bytes
///
/// # Returns
/// * A Keccak256 hash of the prefixed message (Vec<u8>, 32 bytes)
fn hash_eth_message<T: AsRef<[u8]>>(message: T) -> Vec<u8> {
    const PREFIX: &str = "\x19Ethereum Signed Message:\n";
    let msg = message.as_ref();
    let full = [PREFIX.as_bytes(), msg.len().to_string().as_bytes(), msg].concat();
    easy_hasher::raw_keccak256(full).to_vec()
}

/// Converts a compressed public key (33 bytes) to a 20-byte Ethereum address.
///
/// # Arguments
/// * `public_key` - A 33-byte SEC1 compressed public key
///
/// # Returns
/// * `Ok(Vec<u8>)` - The last 20 bytes of the Keccak256 hash of the uncompressed key
/// * `Err` if decoding fails or key length is incorrect
fn get_address_from_public_key(public_key: [u8; 33]) -> DynamicResult<Vec<u8>> {
    // Parse and decompress the SEC1 public key
    let pub_key_arr: [u8; 33] = public_key[..].try_into()?;
    let pub_key = libsecp256k1::PublicKey::parse_compressed(&pub_key_arr)?.serialize();

    // Drop the prefix byte (0x04) and hash the remaining 64 bytes
    let hash = easy_hasher::raw_keccak256(pub_key[1..].to_vec()).to_vec();

    // Ethereum address is the last 20 bytes of the hash
    let address_bytes: [u8; 20] = hash[12..]
        .try_into()
        .map_err(|_| "Invalid address length")?;

    Ok(address_bytes.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_signature() {
        let message = b"4RvWUp3E9YerY78Kn5UyyEQPTiFs0tIr/mhAeCbwIpY=";
        let public_key = "0xd1798d6b74ef965d6a60f45e0036f44aed3dfa1b".to_string();
        let expected_signature = hex::decode(
            "88bd1f104e132178aea55731be455a5c91b3e15b46f2599e9472d926270d458f4116eea0273fb5dc36238992154afc652aa7c1d91569b596db00146b4e5443fa1b"
        ).unwrap();

        // Validate that the signature recovers the expected public key
        let is_valid = validate_ecdsa_signature(&public_key, message, &expected_signature).unwrap();
        assert!(is_valid, "invalid message or signature");
    }

    #[test]
    fn test_invalid_signature() {
        let message = b"4RvWUp3E9YerY78Kn5UyyEQPTiFs0tIr/mhAeCbwIpY=";
        let public_key = "0xd1798d6b74ef965d6a60f45e0036f44aed3dfa1b".to_string();
        let invalid_signature = hex::decode(
            "98bd1f104e132178aea55731be455a5c91b3e15b46f2599e9472d926270d458f4116eea0273fb5dc36238992154afc652aa7c1d91569b596db00146b4e5443fa1b"
        ).unwrap();

        // Validate that the signature fails to recovers the expected public key
        let is_valid = validate_ecdsa_signature(&public_key, message, &invalid_signature).unwrap();
        assert!(!is_valid);
    }
}
