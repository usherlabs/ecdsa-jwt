pub mod challenge;
pub mod ecdsa;
pub mod jwt;
pub mod ethereum;

// Re-export main functions for easier access
pub use ecdsa::verify_signature;
