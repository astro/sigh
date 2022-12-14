use openssl::pkey::{PKey, Private, Public};

use crate::Error;

/// Key that is serializable from/to PEM
pub trait Key: Sized {
    /// Serialize from PEM
    fn from_pem(pem: &[u8]) -> Result<Self, Error>;
    /// Serialize to PEM
    fn to_pem(&self) -> Result<String, Error>;
}

/// A private key for signing
#[derive(Debug, Clone)]
pub struct PrivateKey(pub PKey<Private>);

impl Key for PrivateKey {
    fn from_pem(pem: &[u8]) -> Result<Self, Error> {
        Ok(PrivateKey(PKey::private_key_from_pem(pem)?))
    }

    fn to_pem(&self) -> Result<String, Error> {
        let bytes = self.0.private_key_to_pem_pkcs8()?;
        let pem = String::from_utf8(bytes)?;
        Ok(pem)
    }
}

/// A public key for verification
#[derive(Debug, Clone)]
pub struct PublicKey(pub PKey<Public>);

impl Key for PublicKey {
    fn from_pem(pem: &[u8]) -> Result<Self, Error> {
        Ok(PublicKey(PKey::public_key_from_pem(pem)?))
    }

    fn to_pem(&self) -> Result<String, Error> {
        let bytes = self.0.public_key_to_pem()?;
        let pem = String::from_utf8(bytes)?;
        Ok(pem)
    }
}
