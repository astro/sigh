use openssl::pkey::PKey;
use openssl::rsa::{Rsa, Padding};
use openssl::hash::MessageDigest;
use crate::{Error, Key};
use crate::{PrivateKey, PublicKey};

/// `rsa-sha256` algorithm
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RsaSha256;

impl super::Algorithm for RsaSha256 {
    fn name(&self) -> &'static str {
        "rsa-sha256"
    }


    fn message_digest(&self) -> Option<MessageDigest> {
        Some(MessageDigest::sha256())
    }

    fn rsa_padding(&self) -> Option<Padding> {
        Some(Padding::PKCS1)
    }

    fn generate_keys(&self) -> Result<(PrivateKey, PublicKey), Error> {
        let rsa = Rsa::generate(4096 /* bits */)?;
        let public_key = PublicKey::from_pem(&rsa.public_key_to_pem()?)?;
        let private_key = PKey::from_rsa(rsa)?;

        Ok((PrivateKey(private_key), public_key))
    }
}
