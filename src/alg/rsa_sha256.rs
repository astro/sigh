use openssl::sign::{Signer, Verifier};
use openssl::rsa::{Padding, Rsa};
use openssl::hash::MessageDigest;
use crate::{Error, Key};
use crate::key::rsa::{PrivateKey, PublicKey};

/// `rsa-sha256` algorithm
pub struct RsaSha256;

impl RsaSha256 {
    /// Generate private and public RSA key
    pub fn generate_keys(&self) -> Result<(PrivateKey, PublicKey), Error> {
        let rsa = Rsa::generate(4096 /* bits */)?;
        let private_key = PrivateKey::from_pem(&rsa.private_key_to_pem()?)?;
        let public_key = PublicKey::from_pem(&rsa.public_key_to_pem()?)?;
        Ok((private_key, public_key))
    }
}

impl super::Algorithm for RsaSha256 {
    type PrivateKey = PrivateKey;
    type PublicKey = PublicKey;

    fn name(&self) -> &'static str {
        "rsa-sha256"
    }

    fn sign(&self, private_key: &Self::PrivateKey, data: &[u8]) -> Result<Vec<u8>, Error> {
        let pkey = &private_key.0;
        let mut signer = Signer::new(MessageDigest::sha256(), &pkey)?;
        signer.set_rsa_padding(Padding::PKCS1)?;
        signer.update(data)?;
        let mut len = signer.len()?;
        let mut buf = vec![0; len];
        len = signer.sign(&mut buf)?;
        buf.truncate(len);
        Ok(buf)
    }

    fn verify(&self, public_key: &Self::PublicKey, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        let pkey = &public_key.0;
        let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey)?;
        verifier.set_rsa_padding(Padding::PKCS1)?;
        verifier.update(data)?;
        Ok(verifier.verify(&signature)?)
    }
}
