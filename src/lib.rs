//! HTTP signature generation and verification for ActivityPub

#![deny(unused, missing_docs)]
mod error;
/// Signature algorithms
pub mod alg;
mod key;
mod signature;
mod signature_header;

/// Key serialization/deserialization
pub use key::Key;
pub use signature::{
    Signature,
    SigningConfig,
};

/// General error type
pub use error::Error;
