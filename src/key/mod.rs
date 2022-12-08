use crate::Error;

pub mod rsa;

/// Key that is serializable from/to PEM
pub trait Key: Sized {
    /// Serialize from PEM
    fn from_pem(pem: &[u8]) -> Result<Self, Error>;
    /// Serialize to PEM
    fn to_pem(&self) -> Result<String, Error>;
}
