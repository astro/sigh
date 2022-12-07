use openssl::sign::{Signer, Verifier};
use openssl::rsa::Rsa;
use openssl::pkey::PKey;
use openssl::hash::MessageDigest;

pub struct RsaSha256;

impl super::Algorithm for RsaSha256 {
    fn sign(&self) {
    }

    fn verify(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
        let pkey = if let Ok(pkey) = PKey::public_key_from_pem(public_key) {
            pkey
        } else {
            return false;
        };
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();
        if let Err(_) = verifier.update(data) {
            return false;
        }
        verifier.verify(&signature).unwrap_or(false)
    }
}
