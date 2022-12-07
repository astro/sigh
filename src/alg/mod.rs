mod rsa_v1_5_sha256;

pub fn by_name(name: &str) -> Option<impl Algorithm> {
    match name {
        "rsa-sha256" => Some(rsa_v1_5_sha256::RsaV15Sha256),
        // TODO: mastodon also seems to support "hs2019"
        _ => None,
    }
}


pub trait Algorithm {
    fn sign(&self);
    fn verify(&self, public_key: &[u8], data: &[u8], signature: &[u8]) -> bool;
}
