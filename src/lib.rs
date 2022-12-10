//! HTTP signature generation and verification for ActivityPub
//!
//! # Usage
//!
//! ## Generate a keypair
//!
//! ```
//! use sigh::Key;
//! use sigh::alg::{Algorithm, RsaSha256};
//!
//! let (private_key, public_key) = RsaSha256.generate_keys().unwrap();
//! publish(public_key.to_pem().unwrap());
//! save(private_key.to_pem().unwrap());
//!
//! fn publish(public_key: String) {
//!   // include public_key in an ActivityPub actor's json
//! }
//! fn save(private_key: String) {
//!   // stash private_key away securely
//! }
//! ```
//!
//! ## Sign a HTTP request
//!
//! ```
//! use http::Request;
//! use sigh::{Key, PrivateKey, SigningConfig};
//! use sigh::alg::RsaSha256;
//!
//! fn sign_request<B>(request: &mut Request<B>, private_key_pem: &[u8]) -> Result<(), sigh::Error> {
//!     let private_key = PrivateKey::from_pem(private_key_pem)?;
//!     SigningConfig::new(RsaSha256, &private_key, "my-key-id")
//!         .sign(request)
//! }
//! ```
//!
//! ## Verify a HTTP request
//!
//! ```
//! use http::Request;
//! use sigh::{Key, PublicKey, Signature};
//!
//! fn lookup_public_key_pem(key_id: Option<&str>) -> Option<&[u8]> {
//!     // retrieve the public_key in PEM format
//!
//!     None
//! }
//!
//! fn verify_request<B>(request: &Request<B>) -> bool {
//!     let signature = Signature::from(request);
//!     let key_id = signature.key_id();
//!     let public_key_pem = match lookup_public_key_pem(key_id) {
//!         Some(public_key_pem) => public_key_pem,
//!         None => return false,
//!     };
//!     let public_key = match PublicKey::from_pem(public_key_pem) {
//!         Ok(public_key) => public_key,
//!         Err(_) => return false,
//!     };
//!     signature.verify(&public_key)
//!         .unwrap_or_else(|_| false)
//! }
//! ```

#![deny(unused, missing_docs)]

mod error;
/// Signature algorithms
pub mod alg;
mod key;
mod signature;
mod signature_header;

/// Key serialization/deserialization
pub use key::{Key, PrivateKey, PublicKey};
pub use signature::{
    Signature,
    SigningConfig,
};

/// General error type
pub use error::Error;
