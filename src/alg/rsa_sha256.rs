use openssl::sign::{Signer, Verifier};
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;
use crate::Error;

pub struct RsaSha256;

impl super::Algorithm for RsaSha256 {
    fn sign(&self) {
    }

    fn verify(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        let pkey = PKey::public_key_from_pem(public_key)?;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)?;
        verifier.update(data)?;
        Ok(verifier.verify(&signature)?)
    }
}
