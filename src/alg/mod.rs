use crate::{Error, PrivateKey, PublicKey};
mod rsa_sha256;
mod hs2019;

use openssl::{hash::MessageDigest, sign::{Signer, Verifier}, rsa::Padding};
pub use rsa_sha256::RsaSha256;
pub use hs2019::Hs2019;

/// Find signature algorithm implementation by name
pub fn by_name(name: &str) -> Option<Box<dyn Algorithm>> {
    match name {
        "rsa-sha256" => Some(Box::new(rsa_sha256::RsaSha256)),
        "hs2019" => Some(Box::new(hs2019::Hs2019)),
        _ => None,
    }
}

/// Signature algorithm
pub trait Algorithm {
    /// Signature algorithm name
    fn name(&self) -> &'static str;

    /// Generate private and public keys suitable for this algorithm
    fn generate_keys(&self) -> Result<(PrivateKey, PublicKey), Error>;

    /// `openssl::hash::MessageDigest` specified by this algorithm
    fn message_digest(&self) -> Option<MessageDigest>;

    /// RSA padding mode specified by this algorithm
    fn rsa_padding(&self) -> Option<Padding> {
        None
    }

    /// Sign data
    fn sign(&self, private_key: &PrivateKey, data: &[u8]) -> Result<Vec<u8>, Error> {
        let pkey = &private_key.0;
        let mut signer = match self.message_digest() {
            Some(message_digest) =>
                Signer::new(message_digest, &pkey)?,
            None =>
                Signer::new_without_digest(&pkey)?,
        };
        if let Some(padding) = self.rsa_padding() {
            signer.set_rsa_padding(padding)?;
        }
        let mut len = signer.len()?;
        let mut buf = vec![0; len];
        len = signer.sign_oneshot(&mut buf, data)?;
        buf.truncate(len);
        Ok(buf)
    }

    /// Verify a signature
    fn verify(&self, public_key: &PublicKey, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        let pkey = &public_key.0;
        let mut verifier = match self.message_digest() {
            Some(message_digest) =>
                Verifier::new(message_digest, &pkey)?,
            None =>
                Verifier::new_without_digest(&pkey)?,
        };
        if let Some(padding) = self.rsa_padding() {
            verifier.set_rsa_padding(padding)?;
        }
        Ok(verifier.verify_oneshot(&signature, data)?)
    }
}
