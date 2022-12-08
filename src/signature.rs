use reqwest::{
    header::{HeaderMap, HeaderValue},
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
    header: Option<&'a SignatureHeader<'a>>,
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
        Signature {
            request_target,
            headers,
            header: None,
        }
    }
}

impl<'a> Signature<'a> {
    fn header(&self) -> Result<SignatureHeader, Error> {
        match self.header {
            Some(header) => Ok(header.clone()),
            None => self.headers.get("Signature")
                .ok_or(Error::SignatureHeaderMissing)?
                .to_str()
                .map_err(Error::HeaderValue)
                .and_then(SignatureHeader::parse),
        }
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

    pub fn verify(&self, public_key_pem: &str) -> Result<bool, Error> {
        // TODO: verify created, expires
        // TODO: require minimal set of headers
        let signing_string = self.signing_string()?;
        let header = self.header()?;
        let alg = crate::alg::by_name(header.algorithm)
            .ok_or(Error::UnknownAlgorithm(header.algorithm.to_string()))?;
        let public_key = alg.public_key_from_pem(public_key_pem.as_bytes())?;
        let signature = header.signature_bytes()?;
        alg.verify(&public_key, signing_string.as_bytes(), &signature)
    }
}

pub struct SigningConfig<A: Algorithm> {
    algorithm: A,
    private_key: A::PrivateKey,
    key_id: String,
    signed_headers: &'static [&'static str],
    pub other: Vec<(String, String)>,
}

impl<A: Algorithm> SigningConfig<A> {
    pub fn new(algorithm: A, private_key: A::PrivateKey, key_id: impl Into<String>) -> Self {
        SigningConfig {
            algorithm,
            private_key,
            key_id: key_id.into(),
            signed_headers: &[
                "(request-target)",
                "host", "date",
                "digest", "content-type"
            ],
            other: vec![],
        }
    }

    pub fn sign(&self, request: &mut Request) -> Result<(), Error> {
        let mut header = SignatureHeader {
            key_id: Some(&self.key_id),
            algorithm: self.algorithm.name(),
            headers: self.signed_headers.iter().cloned().collect(),
            signature: &"-",
            other: self.other.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect(),
        };
        let mut signature = Signature::from(&*request);
        signature.header = Some(&header);
        let signing_string = signature.signing_string()?;
        let value = self.algorithm.sign(&self.private_key, &signing_string.as_bytes())?;
        let value = base64::encode(value);
        header.signature = &value;
        request.headers_mut().insert("signature", HeaderValue::from_str(&header.to_string()).map_err(Error::SerializeHeader)?);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use reqwest::{header::HeaderValue, Method, Request, Url};
    use crate::key::Key;
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

    #[test]
    fn sign() {
        let mut request = Request::new(Method::POST, Url::parse("https://relay.fedi.buzz/test").unwrap());
        let headers = request.headers_mut();
        headers.insert("host", HeaderValue::from_static(&"relay.fedi.buzz"));
        headers.insert("date", HeaderValue::from_static(&"Wed, 07 Dec 2022 17:25:25 GMT"));
        headers.insert("digest", HeaderValue::from_static(&"SHA-256=Kr9tlIjunJw2X/ceUWcezSYxI+OTxQPxpyCrOS0yvLc="));
        headers.insert("content-type", HeaderValue::from_static(&"application/activity+json"));
        let (private_key, _) = crate::alg::RsaSha256.generate_keys().unwrap();
        SigningConfig::new(crate::alg::RsaSha256, private_key, "key1")
            .sign(&mut request).unwrap();
        request.headers().get("signature").unwrap();
    }

    #[test]
    fn round_trip() {
        let mut request = Request::new(Method::POST, Url::parse("https://relay.fedi.buzz/test").unwrap());
        let headers = request.headers_mut();
        headers.insert("host", HeaderValue::from_static(&"relay.fedi.buzz"));
        headers.insert("date", HeaderValue::from_static(&"Wed, 07 Dec 2022 17:25:25 GMT"));
        headers.insert("digest", HeaderValue::from_static(&"SHA-256=Kr9tlIjunJw2X/ceUWcezSYxI+OTxQPxpyCrOS0yvLc="));
        headers.insert("content-type", HeaderValue::from_static(&"application/activity+json"));
        let (private_key, public_key) = crate::alg::RsaSha256.generate_keys().unwrap();
        SigningConfig::new(crate::alg::RsaSha256, private_key.clone(), "key1")
            .sign(&mut request).unwrap();

        let signature = Signature::from(&request);
        assert_eq!(signature.verify(&public_key.to_pem().unwrap()).unwrap(), true);
    }
}
