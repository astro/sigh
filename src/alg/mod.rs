use crate::{Error, PrivateKey, PublicKey};
mod rsa_sha256;

pub use rsa_sha256::RsaSha256;

/// Find signature algorithm implementation by name
pub fn by_name(name: &str) -> Option<Box<dyn Algorithm>> {
    match name {
        "rsa-sha256" => Some(Box::new(rsa_sha256::RsaSha256)),
        // TODO: "hs2019" => Some(Box::new(eddsa_sha512::EddsaSha512)),
        _ => None,
    }
}

/// Signature algorithm
pub trait Algorithm {
    /// Signature algorithm name
    fn name(&self) -> &'static str;

    /// Sign data
    fn sign(&self, private_key: &PrivateKey, data: &[u8]) -> Result<Vec<u8>, Error>;

    /// Verify a signature
    fn verify(&self, public_key: &PublicKey, data: &[u8], signature: &[u8]) -> Result<bool, Error>;
}
