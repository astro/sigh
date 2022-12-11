use std::string::FromUtf8Error;

use http::header::{ToStrError, InvalidHeaderValue};

/// General error type
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Missing a field in the `Signature:` header
    #[error("Missing a field in the `Signature:` header")]
    MissingField(&'static str),
    /// `Signature:` header is missing
    #[error("`Signature:` header is missing")]
    SignatureHeaderMissing,
    /// Cannot use invalid bytes as HTTP header value
    #[error("Cannot use invalid bytes as HTTP header value")]
    HeaderValue(ToStrError),
    /// Cannot serialize HTTP header
    #[error("Cannot serialize HTTP header")]
    SerializeHeader(InvalidHeaderValue),
    /// Signature algorithm not implemented
    #[error("Signature algorithm not implemented")]
    UnknownAlgorithm(String),
    /// Error parsing the `Signature:` header
    #[error("Error parsing the `Signature:` header")]
    ParseSignatureHeader(nom::Err<nom::error::Error<String>>),
    /// Cannot decode base64
    #[error("Cannot decode base64")]
    SignatureBase64(base64::DecodeError),
    /// Cryptographic issue
    #[error("Cryptographic issue")]
    OpenSsl(#[from] openssl::error::ErrorStack),
    /// Invalid UTF-8
    #[error("Invalid UTF-8")]
    Utf8(#[from] FromUtf8Error),
}

