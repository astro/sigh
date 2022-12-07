use ring::signature::{
    UnparsedPublicKey,
    RSA_PKCS1_2048_8192_SHA256,
};

pub struct RsaV15Sha256;

impl super::Algorithm for RsaV15Sha256 {
    fn sign(&self) {
    }

    fn verify(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public_key)
            .verify(data, signature)
            .map(|()| true)
            .map_err(|e| eprintln!("{:?}", e))
            .unwrap_or(false)
    }
}
