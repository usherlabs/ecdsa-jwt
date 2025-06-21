// examples/basic_usage.rs

use base64::prelude::*;
use ecdsa_jwt::{
    auth::{AuthRequest, AuthService},
    config::JwtConfig,
};
use secrecy::Secret;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ECDSA-JWT Basic Usage Example");

    // 1. Setup authentication service
    let jwt_config = JwtConfig {
        secret: Secret::new(BASE64_STANDARD.encode("example-secret-key")),
        ttl: 3600, // 1 hour
    };
    let auth_service = AuthService::new(jwt_config);

    // 2. Simulate challenge storage (in real app, use Redis/DB)
    let mut challenges: HashMap<String, String> = HashMap::new();

    // 3. Generate challenge
    let challenge = auth_service.generate_challenge();
    let session_id = "example-session-123";
    challenges.insert(session_id.to_string(), challenge.clone());

    println!("Generated challenge: {}", challenge);
    println!("Stored with session ID: {}", session_id);

    // 4. Simulate client authentication (this would normally fail without real signature)
    println!("\n Authentication attempt...");

    let auth_request = AuthRequest {
        challenge,
        signature: "dummy-signature-for-example".to_string(),
        public_key_pem: "-----BEGIN PUBLIC KEY-----\nDummyKeyForExample\n-----END PUBLIC KEY-----"
            .to_string(),
    };

    // This will fail, but demonstrates the API structure
    match auth_service.authenticate(auth_request) {
        Ok(response) => {
            println!("Authentication successful!");
            println!("   JWT Token: {}", response.session_token);
            println!("   Session ID: {}", response.session_id);
            println!("   Expires at: {}", response.expires_at);
        }
        Err(e) => {
            println!(" Authentication failed (expected with dummy data): {}", e);
            println!("   In real usage, provide valid signature and public key.");
        }
    }

    // 5. Demonstrate JWT validation with a real token
    println!("\nJWT Token Operations...");

    let session_id = uuid::Uuid::new_v4();
    let jwt_token = ecdsa_jwt::crypto::jwt::create_jwt(session_id, &auth_service.jwt_config)?;

    println!("Created JWT: {}...", &jwt_token[..50]);

    match auth_service.validate_session(&jwt_token) {
        Ok(claims) => {
            println!("Token validation successful!");
            println!("User/Session ID: {}", claims.sub);
            println!("Issued at: {}", claims.iat);
            println!("Expires at: {}", claims.exp);
        }
        Err(e) => {
            println!("Token validation failed: {}", e);
        }
    }

    println!("\nExample completed! Check the documentation for real implementation details.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example_runs() {
        // Test that the example runs without panicking
        main().unwrap();
    }

    #[test]
    fn test_challenge_generation() {
        let jwt_config = JwtConfig {
            secret: Secret::new(BASE64_STANDARD.encode("test-secret")),
            ttl: 3600,
        };
        let auth_service = AuthService::new(jwt_config);

        let challenge = auth_service.generate_challenge();
        assert!(!challenge.is_empty());

        // Challenge should be base64 encoded 32 bytes
        let decoded = BASE64_STANDARD.decode(&challenge).unwrap();
        assert_eq!(decoded.len(), 32);
    }
}
