use openssl::{hash::MessageDigest, pkey::{PKey, self}};
use crate::Error;
use crate::key::{PrivateKey, PublicKey};

/// `hs2019`/Ed25519/EdDsa+sha512 algorithm
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hs2019;

impl super::Algorithm for Hs2019 {
    fn name(&self) -> &'static str {
        "hs2019"
    }

    fn message_digest(&self) -> Option<MessageDigest> {
        // sha512 is implicit for ed25519
        None
    }

    fn generate_keys(&self) -> Result<(PrivateKey, PublicKey), Error> {
        let private_key = PKey::generate_ed25519()?;
        let public_key = PKey::public_key_from_raw_bytes(
            &private_key.raw_public_key()?,
            pkey::Id::ED25519
        )?;

        Ok((PrivateKey(private_key), PublicKey(public_key)))
    }
}
