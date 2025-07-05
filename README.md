# ecdsa-jwt

A Rust library for **ECDSA challenge-based authentication** with **flexible JWT session management**. Provides server-side cryptographic operations for secure, passwordless authentication where clients prove ownership of ECDSA private keys by signing challenges.

## Features

- **ECDSA Signature Verification** - Verify signatures using secp256k1 curve
- **Secure Challenge Generation** - Cryptographically secure 32-byte challenges
- **Flexible JWT Session Management** - Create and validate JWTs with or without embedded public keys
- **Stateless Design** - No built-in storage, you control data persistence
- **Comprehensive Error Handling** - Detailed error types for debugging

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
ecdsa-jwt = "0.1"
```

## Usage

### Authentication Flow

See the authentication flow in the [basic_workflow example](examples/basic_workflow.rs):

```bash
cargo run --example basic_workflow
```

The example demonstrates:

- Challenge generation and storage
- Authentication with signed challenges
- JWT creation with optional public key inclusion
- JWT validation and session management



### Generating ECDSA Keys

#### Using OpenSSL (Recommended)

```bash
# Generate private key
openssl ecparam -genkey -name secp256k1 -out private_key.pem
openssl ec -in private_key.pem -out private_key.pem

# Extract public key
openssl ec -in private_key.pem -pubout -out public_key.pem

# View the keys
cat private_key.pem
cat public_key.pem

# Generate SHA256 hash of public key
cat public_key.pem | openssl dgst -sha256
```

#### Using Rust (p256 crate)

```rust
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::SecretKey;
use rand::rngs::OsRng;
use base64::prelude::*;

// Generate key pair
let private_key = SecretKey::random(&mut OsRng);
let signing_key = SigningKey::from(private_key);
let verifying_key = VerifyingKey::from(&signing_key);

// Export public key as PEM
let public_key_pem = verifying_key.to_encoded_point(false).to_string();
let public_key_pem = format!(
    "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----",
    base64::engine::general_purpose::STANDARD.encode(public_key_pem.as_bytes())
);
```

#### JWT Structure Examples

**With public key (for signature verification):**
```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "exp": 1640995200,
  "iat": 1640991600,
  "key_hash": "a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef12345678",
  "public_key": "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...\n-----END PUBLIC KEY-----"
}
```

**Without public key (smaller, for simple authentication):**
```json
{
  "sub": "550e8400-e29b-41d4-a716-446655440000",
  "exp": 1640995200,
  "iat": 1640991600,
  "key_hash": null,
  "public_key": null
}
```

#### Creating JWTs Manually

```rust
use ecdsa_jwt::crypto::jwt::create_jwt;
use uuid::Uuid;

// Create JWT without public key (smaller size)
let token = create_jwt(session_id, None, &config)?;

// Create JWT with public key
let public_key = Some("-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string());
let token = create_jwt(session_id, public_key, &config)?;
```

### Client-Side Signing Example

```rust
use p256::ecdsa::{SigningKey, VerifyingKey};
use p256::SecretKey;
use rand::rngs::OsRng;
use base64::prelude::*;

// Load private key from PEM file
let private_key_pem = std::fs::read_to_string("private_key.pem").unwrap();
let private_key = SecretKey::from_sec1_pem(&private_key_pem).unwrap();
let signing_key = SigningKey::from(private_key);

// Load public key from PEM file  
let public_key = std::fs::read_to_string("public_key.pem").unwrap();

// Sign a challenge
let challenge = "base64-encoded-challenge-from-server";
let challenge_bytes = base64::decode(challenge).unwrap();
let signature = signing_key.sign(&challenge_bytes);
let signature_b64 = base64::encode(signature.to_bytes());

// Send to server: challenge, signature_b64, and public_key
```

### Individual Functions

```rust
use ecdsa_jwt::{generate_challenge, verify_signature, create_jwt, validate_token};

// Generate challenge
let challenge = generate_challenge();

// Verify signature  
let challenge_bytes = base64::decode(&challenge)?;
let signature_bytes = base64::decode(&signature)?;
verify_signature(&public_key, &challenge_bytes, &signature_bytes)?;

// Create JWT (with optional public key)
let token = create_jwt(session_id, Some(public_key), &jwt_config)?;

// Validate JWT
let claims = validate_token(&token, &jwt_config)?;

// Verify signature using public key from JWT (requires JWT with embedded public key)
use ecdsa_jwt::AuthService;
let auth_service = AuthService::new(jwt_config);
match auth_service.verify_signature_from_jwt(
    &token,
    challenge.as_bytes(),
    &signature_bytes
) {
    Ok(()) => println!("Signature verified using JWT public key!"),
    Err(e) => println!("Verification failed: {}", e),
}
```

## API Reference

### AuthService

```rust
impl AuthService {
    pub fn new(jwt_config: JwtConfig) -> Self;
    pub fn generate_challenge(&self) -> String;
    pub fn authenticate(&self, request: AuthRequest, include_public_key: bool) -> Result<AuthResponse>;
    pub fn validate_session(&self, token: &str) -> Result<Claims>;
    pub fn verify_signature_from_jwt(&self, jwt_token: &str, challenge: &[u8], signature: &[u8]) -> Result<()>;
}
```

### Core Types

```rust
pub struct AuthRequest {
    pub challenge: String,        // Base64-encoded challenge
    pub signature: String,        // Base64-encoded signature
    pub public_key: String,       // Public key
}

pub struct AuthResponse {
    pub session_id: Uuid,        // Session identifier
    pub session_token: String,   // JWT token
    pub expires_at: i64,         // Unix timestamp
}

pub struct JwtConfig {
    pub secret: Secret<String>,  // Base64-encoded secret
    pub ttl: i64,               // Token lifetime (seconds)
}

pub struct Claims {
    pub sub: Uuid,              // Session identifier
    pub exp: i64,              // Expiration timestamp
    pub iat: i64,              // Issued at timestamp
    pub key_hash: Option<String>,      // SHA256 hash of public key (optional)
    pub public_key: Option<String>, // Full public key PEM (optional)
}
```

### Utility Functions

```rust
// Challenge operations
pub fn generate_challenge() -> String;
pub fn decode_challenge(challenge_b64: &str) -> Result<Vec<u8>>;

// Signature verification
pub fn verify_signature(public_key: &str, challenge: &[u8], signature: &[u8]) -> Result<()>;
pub fn verify_signature_b64(public_key: &str, challenge_b64: &str, signature_b64: &str) -> Result<()>;
pub fn verify_signature_eth(public_key: &str, challenge_b64: &str, signature_b64: &str) -> Result<()>;
pub fn verify_signature_pem(public_key: &str, challenge_b64: &str, signature_b64: &str) -> Result<()>;

// JWT operations (public key is optional)
pub fn create_jwt(session_id: Uuid, public_key: Option<String>, config: &JwtConfig) -> Result<String>;
pub fn validate_token(token: &str, config: &JwtConfig) -> Result<Claims>;
pub fn verify_signature_from_jwt(token: &str, config: &JwtConfig, challenge: &[u8], signature: &[u8]) -> Result<()>;
```

## Security Considerations

### JWT Security

- **HMAC-SHA256 signing** - Prevents tampering
- **Expiration timestamps** - Automatic token expiry
- **Cryptographic verification** - Cannot be forged without the secret
- **Stateless design** - No server-side session storage required

### Best Practices

- **Use strong secrets** (at least 256 bits) for JWT signing
- **Set appropriate TTL** (1 hour recommended for most use cases)
- **Always use HTTPS** in production
- **Store challenges securely** with short expiration (5-15 minutes)
- **Remove challenges after use** to prevent replay attacks
- **Validate tokens on every request** to protected resources

### Public Key Management

- **Include public key in JWT** when you need signature verification
- **Use key hash only** for smaller JWTs when full key isn't needed
- **Store key mappings** in database when using hash-only approach
- **Rotate keys regularly** for enhanced security

## Testing

```bash
cargo test
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.