use crate::Error;

pub mod rsa;

pub trait Key: Sized {
    fn from_pem(pem: &[u8]) -> Result<Self, Error>;
    fn to_pem(&self) -> Result<String, Error>;
}

pub trait GenerateKey: Sized {
    fn generate() -> Result<Self, Error>;
}
