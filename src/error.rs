use std::string::FromUtf8Error;

use reqwest::header::{ToStrError, InvalidHeaderValue};

#[derive(Debug)]
pub enum Error {
    MissingField(&'static str),
    SignatureHeaderMissing,
    HeaderValue(ToStrError),
    SerializeHeader(InvalidHeaderValue),
    UnknownAlgorithm(String),
    ParseSignatureHeader(nom::Err<nom::error::Error<String>>),
    SignatureBase64(base64::DecodeError),
    OpenSsl(openssl::error::ErrorStack),
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
