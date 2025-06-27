//! # ecdsa-jwt
//! 
//! A Rust library for **ECDSA challenge-based authentication** with **flexible JWT session management**. 
//! Provides server-side cryptographic operations for secure, passwordless authentication where clients 
//! prove ownership of ECDSA private keys by signing challenges.
//! 
//! ## Features
//! 
//! - **ECDSA Signature Verification** - Verify signatures using secp256k1 curve
//! - **Secure Challenge Generation** - Cryptographically secure 32-byte challenges
//! - **Flexible JWT Session Management** - Create and validate JWTs with or without embedded public keys
//! - **Stateless Design** - No built-in storage, you control data persistence
//! - **Comprehensive Error Handling** - Detailed error types for debugging
//! 
//! ## Quick Start
//! 
//! ```rust
//! use ecdsa_jwt::{AuthService, AuthRequest, JwtConfig};
//! use secrecy::Secret;
//! use base64::prelude::*;
//! 
//! // Setup authentication service
//! let jwt_config = JwtConfig {
//!     secret: Secret::new(BASE64_STANDARD.encode("your-secret-key")),
//!     ttl: 3600, // 1 hour
//! };
//! let auth_service = AuthService::new(jwt_config);
//! 
//! // Generate challenge
//! let challenge = auth_service.generate_challenge();
//! 
//! // Authenticate with signed challenge
//! let auth_request = AuthRequest {
//!     challenge: "base64-encoded-challenge".to_string(),
//!     signature: "base64-encoded-signature".to_string(),
//!     public_key_pem: "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----".to_string(),
//! };
//! 
//! match auth_service.authenticate(auth_request, true) { // true = include public key in JWT
//!     Ok(response) => println!("JWT Token: {}", response.session_token),
//!     Err(e) => println!("Authentication failed: {}", e),
//! }
//! ```
//! 
//! ## Examples
//! 
//! See the [basic_workflow example](examples/basic_workflow.rs) for a complete authentication flow:
//! 
//! ```bash
//! cargo run --example basic_workflow
//! ```
//! 
//! ## Documentation
//! 
//! For detailed API documentation, see the [docs.rs page](https://docs.rs/ecdsa-jwt).

pub mod auth;
pub mod config;
pub mod crypto;
pub mod error;

// Re-export main types for easier access
pub use auth::{AuthService, AuthRequest, AuthResponse};
pub use config::JwtConfig;
pub use crypto::challenge::generate_challenge;
pub use crypto::ecdsa::verify_signature;
pub use crypto::jwt::{create_jwt, validate_token};
pub use error::{AuthError, Result};
