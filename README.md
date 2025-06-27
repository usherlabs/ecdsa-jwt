# ecdsa-jwt

A Rust library for **ECDSA challenge-based authentication** with **JWT session management**. Provides server-side cryptographic operations for secure, passwordless authentication where clients prove ownership of ECDSA private keys by signing challenges.

## Features

- **ECDSA Signature Verification** - Verify signatures using secp256k1 curve
- **Secure Challenge Generation** - Cryptographically secure 32-byte challenges
- **JWT Session Management** - Create and validate session tokens
- **Stateless Design** - No built-in storage, you control data persistence
- **Comprehensive Error Handling** - Detailed error types for debugging

## Publishing

This crate is automatically published to [crates.io](https://crates.io/crates/ecdsa-jwt) using GitHub Actions when a new version tag is pushed.

### Setup for Publishing

1. **Add Cargo Token Secret**: In your GitHub repository settings, add a secret named `CARGO_TOKEN` with your crates.io API token.

2. **Create a Release**: To publish a new version:
   ```bash
   # Update version in Cargo.toml
   # Create and push a new tag
   git tag v0.1.1
   git push origin v0.1.1
   ```

3. **Manual Publishing**: You can also trigger publishing manually from the GitHub Actions tab.

The workflow will:
- Build the project
- Run tests
- Publish to crates.io under the `usherlabs` organisation
- Contact: `labs@usher.so`

## Quick Start

Add to your `Cargo.toml`:

```toml
[dependencies]
ecdsa-jwt = "0.1"
```

## Usage

### Using OpenSSL to Generate Keys

You can generate ECDSA keys using OpenSSL:

```bash
# Generate private key
openssl ecparam -genkey -name secp256k1 -out private_key.pem
openssl ec -in private_key.pem -out private_key.pem

# Extract public key
openssl ec -in private_key.pem -pubout -out public_key.pem

# View the keys
cat private_key.pem
cat public_key.pem
```


### Basic Authentication Flow

```rust
use ecdsa_jwt::{AuthService, AuthRequest, JwtConfig};
use secrecy::Secret;
use base64::prelude::*;
use std::collections::HashMap;

// 1. Setup authentication service
let jwt_config = JwtConfig {
    secret: Secret::new(BASE64_STANDARD.encode("your-secret-key")),
    ttl: 3600, // 1 hour
};
let auth_service = AuthService::new(jwt_config);

// 2. Your challenge storage (Redis, database, etc.)
let mut challenges: HashMap<String, String> = HashMap::new();

// 3. Generate challenge (server endpoint)
let challenge = auth_service.generate_challenge();
let session_id = "unique-session-id";
challenges.insert(session_id.to_string(), challenge.clone());

// 4. Authenticate signed challenge (server endpoint)
let stored_challenge = challenges.remove(session_id).unwrap();
let auth_request = AuthRequest {
    challenge: stored_challenge,
    signature: "base64-encoded-signature".to_string(),
    public_key_pem: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string(),
};

match auth_service.authenticate(auth_request) {
    Ok(response) => {
        println!("JWT Token: {}", response.session_token);
        // Use JWT for subsequent API requests
    }
    Err(e) => println!("Authentication failed: {}", e),
}

// 5. Validate JWT tokens
match auth_service.validate_session(&jwt_token) {
    Ok(claims) => println!("Valid session for user: {}", claims.sub),
    Err(_) => println!("Invalid token"),
}
```

### Complete Client-Side Example

Here's a complete client-side example using the generated keys:

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
let public_key_pem = std::fs::read_to_string("public_key.pem").unwrap();

// Sign a challenge
let challenge = "base64-encoded-challenge-from-server";
let challenge_bytes = base64::decode(challenge).unwrap();
let signature = signing_key.sign(&challenge_bytes);
let signature_b64 = base64::encode(signature.to_bytes());

// Send to server: challenge, signature_b64, and public_key_pem
```

### Individual Functions

```rust
use ecdsa_jwt::{generate_challenge, verify_signature, create_jwt, validate_token};

// Generate challenge
let challenge = generate_challenge();

// Verify signature  
let challenge_bytes = base64::decode(&challenge)?;
let signature_bytes = base64::decode(&signature)?;
verify_signature(&public_key_pem, &challenge_bytes, &signature_bytes)?;

// Create JWT
let token = create_jwt(session_id, &jwt_config)?;

// Validate JWT
let claims = validate_token(&token, &jwt_config)?;
```

## API Reference

### AuthService

```rust
impl AuthService {
    pub fn new(jwt_config: JwtConfig) -> Self;
    pub fn generate_challenge(&self) -> String;
    pub fn authenticate(&self, request: AuthRequest) -> Result<AuthResponse>;
    pub fn validate_session(&self, token: &str) -> Result<Claims>;
}
```

### Core Types

```rust
pub struct AuthRequest {
    pub challenge: String,        // Base64-encoded challenge
    pub signature: String,        // Base64-encoded signature
    pub public_key_pem: String,   // PEM-encoded public key
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
    pub sub: Uuid,  // User/session ID
    pub exp: i64,   // Expiration timestamp
    pub iat: i64,   // Issued at timestamp
}
```

### Utility Functions

```rust
// Challenge operations
pub fn generate_challenge() -> String;
pub fn decode_challenge(challenge_b64: &str) -> Result<Vec<u8>>;

// Signature verification
pub fn verify_signature(public_key_pem: &str, challenge: &[u8], signature: &[u8]) -> Result<()>;
pub fn verify_signature_b64(public_key_pem: &str, challenge_b64: &str, signature_b64: &str) -> Result<()>;

// JWT operations
pub fn create_jwt(session_id: Uuid, config: &JwtConfig) -> Result<String>;
pub fn validate_token(token: &str, config: &JwtConfig) -> Result<Claims>;
```

## Security Notes

- **Challenge storage is your responsibility** - Use Redis, database, or secure cache
- **Always use HTTPS** in production
- **Challenges should expire quickly** (5-15 minutes recommended)
- **Remove challenges after use** to prevent replay attacks
- **Private key operations happen client-side** - This library only verifies signatures

## Testing

```bash
cargo test
```

## License

This project is licensed under the ISC License - see the [LICENSE](https://opensource.org/license/isc-license-txt) file for details.