use std::string::FromUtf8Error;

use reqwest::header::{ToStrError, InvalidHeaderValue};

/// General error type
#[derive(Debug)]
pub enum Error {
    /// Missing a field in the `Signature:` header
    MissingField(&'static str),
    /// `Signature:` header is missing
    SignatureHeaderMissing,
    /// Cannot use invalid bytes as HTTP header value
    HeaderValue(ToStrError),
    /// Cannot serialize HTTP header
    SerializeHeader(InvalidHeaderValue),
    /// Signature algorithm not implemented
    UnknownAlgorithm(String),
    /// Error parsing the `Signature:` header
    ParseSignatureHeader(nom::Err<nom::error::Error<String>>),
    /// Cannot decode base64
    SignatureBase64(base64::DecodeError),
    /// Cryptographic issue
    OpenSsl(openssl::error::ErrorStack),
    /// Invalid UTF-8
    Utf8(FromUtf8Error),
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Error::OpenSsl(e)
    }
}

impl From<FromUtf8Error> for Error {
    fn from(e: FromUtf8Error) -> Self {
        Error::Utf8(e)
    }
}
