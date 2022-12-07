use reqwest::header::ToStrError;

#[derive(Debug)]
pub enum Error {
    MissingField(&'static str),
    SignatureHeaderMissing,
    HeaderValue(ToStrError),
    UnknownAlgorithm(String),
    ParseSignatureHeader(nom::Err<nom::error::Error<String>>),
    SignatureBase64(base64::DecodeError),
    OpenSsl(openssl::error::ErrorStack),
}

impl From<openssl::error::ErrorStack> for Error {
    fn from(e: openssl::error::ErrorStack) -> Self {
        Error::OpenSsl(e)
    }
}
