use nom::AsBytes;
use reqwest::{
    header::HeaderMap,
    Request,
};
use crate::{
    alg::Algorithm,
    Error,
    signature_header::SignatureHeader,
};

pub struct Signature<'a> {
    request_target: String,
    headers: &'a HeaderMap,
}

impl<'a> From<&'a Request> for Signature<'a> {
    fn from(req: &'a Request) -> Self {
        let method = req.method().as_str().to_lowercase();
        let url = req.url();
        let path_query = url.join("/")
            .ok()
            .and_then(|root_url| root_url.make_relative(&url))
            .unwrap_or_else(|| String::from(url.clone()));
        let request_target = format!("{} /{}", method, path_query);
        let headers = req.headers();
        Signature { request_target, headers }
    }
}

impl<'a> Signature<'a> {
    fn header(&self) -> Result<SignatureHeader, Error> {
        self.headers.get("Signature")
            .ok_or(Error::SignatureHeaderMissing)?
            .to_str()
            .map_err(Error::HeaderValue)
            .and_then(SignatureHeader::parse)
    }

    fn signing_string(&self) -> Result<String, Error> {
        let header = self.header()?;
        Ok(header.headers.iter()
             .enumerate()
             .map(|(i, key)| {
                 let key_s = key.to_lowercase();
                 let newline = if i == 0 {
                     ""
                 } else {
                     "\n"
                 };
                 let value = match *key {
                     "(request-target)" => &self.request_target,
                     "(created)" => header.other.iter()
                         .find(|(key, _)| *key == "created")
                         .map(|(_, value)| *value)
                         .unwrap_or(&""),
                     "(expires)" => header.other.iter()
                         .find(|(key, _)| *key == "expires")
                         .map(|(_, value)| *value)
                         .unwrap_or(&""),
                     _ => {
                         self.headers.get(*key)
                             .and_then(|value| value.to_str().ok())
                             .unwrap_or(&"")
                     }
                 };
                 format!("{}{}: {}", newline, key_s, value)
             }).collect())
    }

    pub fn key_id(&self) -> Option<&str> {
        self.header().ok()?.key_id
    }

    pub fn verify(&self, public_key: &str) -> Result<bool, Error> {
        // TODO: verify created, expires
        // TODO: require minimal set of headers
        let signing_string = self.signing_string()?;
        let header = self.header()?;
        let alg = crate::alg::by_name(header.algorithm)
            .ok_or(Error::UnknownAlgorithm(header.algorithm.to_string()))?;
        let signature = header.signature_bytes()?;
        alg.verify(public_key.as_bytes(), signing_string.as_bytes(), &signature)
    }
}

#[cfg(test)]
mod tests {
    use reqwest::{header::HeaderValue, Method, Request, Url};
    use super::*;

    /// Real-world Mastodon 4.0 data
    #[test]
    fn verify_example_post() {
        let mut request = Request::new(Method::POST, Url::parse("https://relay.fedi.buzz/test").unwrap());
        let headers = request.headers_mut();
        headers.insert("host", HeaderValue::from_static(&"relay.fedi.buzz"));
        headers.insert("date", HeaderValue::from_static(&"Wed, 07 Dec 2022 17:25:25 GMT"));
        headers.insert("digest", HeaderValue::from_static(&"SHA-256=Kr9tlIjunJw2X/ceUWcezSYxI+OTxQPxpyCrOS0yvLc="));
        headers.insert("content-type", HeaderValue::from_static(&"application/activity+json"));
        headers.insert("signature", HeaderValue::from_static(&r#"keyId="https://c3d2.social/actor#main-key",algorithm="rsa-sha256",headers="(request-target) host date digest content-type",signature="jeZwvES9qqa6atwASUXHLSynt3rd8OhoNQvnjqhdYkChxahG0QnQDJQcFkEptyjVgODGOqEkdYuqwsJfCh0CLvLMPS0TBefyzFbTB+BVtIWcCANnCNLWlKup0aRqPoH9reN0NaEIqj8JqhN/Bhh2THJdHWAWexCnLQbiKQ2Dy+lk697wSTQ1H4sh8xd1ZtgCPXaoO3Q6oobuBs/d/hcKuxuPFHvikbtQaQfUQjG5MtDm994HkqpYx/+QMfYPw7lcQVStFZ3BbQgrfs4g83OPo2+uu6Q+KQ5ZxR6oHd9N3nmpZO2f+XBZ3j767kVgTnPrHAiqCGX7I3+M8PqAAWERYg==""#));
        let public_key = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAulcRhqjl6GZG9l+Ye29J\ncOYSTpS+rvGvc4YQtIbd08P2jLaiw4k+Nj90sClLV5fQzNG5fo+S8dR85U6VqyL5\nGpixD6x0kuclyBjuTDxd9gh+voix5MVSFuOXM88X5z8glfkiQd/os7NmWgTM9mXI\nsy7q8ZwhaMmijEK2E53ms06yDAeaO3/uCcUt1+CRUOxCEiRf6nMo9SC3ceFG/uma\n/5ck8QgOcxRvCpfH+q25q7qVxDzeWDAfAXnyGybdxiNfJ/9qrCQ05o5BDI3s6ED0\nuPfZdThhEAM/5k3hozDTXZ5umVA9QsV53Kc73z8w7H1Rb+6acfRca+6kFlRdM3Gd\nMwIDAQAB\n-----END PUBLIC KEY-----\n";

        let signature = Signature::from(&request);
        assert_eq!(signature.verify(&public_key).unwrap(), true);
    }
}
