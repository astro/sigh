use crate::{Error, Key};
mod rsa_sha256;

pub use rsa_sha256::RsaSha256;

/// Find signature algorithm implementation by name
pub fn by_name(name: &str) -> Option<impl Algorithm> {
    match name {
        "rsa-sha256" => Some(rsa_sha256::RsaSha256),
        // TODO: mastodon also seems to support "hs2019"
        _ => None,
    }
}

/// Signature algorithm
pub trait Algorithm {
    /// Private key type
    type PrivateKey: Key;
    /// Public key type
    type PublicKey: Key;

    /// Helper function
    fn private_key_from_pem(&self, pem: &[u8]) -> Result<Self::PrivateKey, Error> {
        Self::PrivateKey::from_pem(pem)
    }

    /// Helper function
    fn public_key_from_pem(&self, pem: &[u8]) -> Result<Self::PublicKey, Error> {
        Self::PublicKey::from_pem(pem)
    }

    /// Signature algorithm name
    fn name(&self) -> &'static str;

    /// Sign data
    fn sign(&self, private_key: &Self::PrivateKey, data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Verify a signature
    fn verify(&self, public_key: &Self::PublicKey, data: &[u8], signature: &[u8]) -> Result<bool, Error>;
}
