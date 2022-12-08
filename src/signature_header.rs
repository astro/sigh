use nom::{
    branch::alt,
    character::complete::{alphanumeric1, char, multispace0},
    combinator::eof,
    multi::separated_list0,
    InputTakeAtPosition,
    IResult,
};
use crate::Error;

/// A parsed representation of the `Signature:` header
#[derive(Debug, Clone)]
pub(crate) struct SignatureHeader<'a> {
    pub key_id: Option<&'a str>,
    pub algorithm: &'a str,
    pub headers: Vec<&'a str>,
    pub signature: &'a str,
    pub other: Vec<(&'a str, &'a str)>
}

impl<'a> SignatureHeader<'a> {
    pub fn to_string(&self) -> String {
        let mut result = String::with_capacity(512);
        let mut i = 0;
        let mut push = |k: &str, v: &str| {
            if i > 0 {
                result.push_str(", ");
            }
            i += 1;

            result.push_str(k);
            result.push('=');
            if v.contains(' ') {
                result.push('\"');
                result.push_str(v);
                result.push('\"');
            } else {
                result.push_str(v);
            }
        };
        if let Some(key_id) = self.key_id {
            push("keyId", key_id);
        }
        push("algorithm", self.algorithm);
        push("headers", &self.headers.iter()
             .enumerate()
             .map(|(i, header)|
                  format!("{}{}", if i == 0 { "" } else { " " }, header)
             ).collect::<String>());
        push("signature", self.signature);
        for (k, v) in &self.other {
            push(*k, *v);
        }
        result
    }

    pub fn signature_bytes(&self) -> Result<Vec<u8>, Error> {
        base64::decode(self.signature)
            .map_err(Error::SignatureBase64)
    }

    pub fn parse(input: &'a str) -> Result<Self, Error> {
        let (_, fields) = parse_header(input)
            .map_err(|e| Error::ParseSignatureHeader(e.to_owned()))?;

        let mut key_id = None;
        let mut algorithm = None;
        let mut headers = None;
        let mut signature = None;
        let mut other = Vec::with_capacity(fields.len().saturating_sub(4));
        for (key, value) in fields.into_iter() {
            match key {
                "keyId" =>
                    key_id = Some(value),
                "algorithm" =>
                    algorithm = Some(value),
                "headers" =>
                    headers = Some(
                        value.split(char::is_whitespace)
                            .filter(|s| *s != "")
                            .collect()
                    ),
                "signature" =>
                    signature = Some(value),
                _ =>
                    other.push((key, value)),
            }
        }
        Ok(SignatureHeader {
            key_id,
            algorithm: algorithm.ok_or(Error::MissingField("algorithm"))?,
            headers: headers.ok_or(Error::MissingField("headers"))?,
            signature: signature.ok_or(Error::MissingField("signature"))?,
            other,
        })
    }
}

fn parse_header(input: &str) -> IResult<&str, Vec<(&str, &str)>> {
    let (input, fields) = separated_list0(
        char(','),
        |input| {
            let (input, _) = multispace0(input)?;
            let (input, key) = alphanumeric1(input)?;
            let (input, _) = multispace0(input)?;
            let (input, _) = char('=')(input)?;
            let (input, _) = multispace0(input)?;
            let (input, value) = alt((
                |input| {
                    let (input, _): (&str, _) = char('"')(input)?;
                    let (input, value) = input.split_at_position_complete(
                        |c| c == '"'
                    )?;
                    let (input, _) = char('"')(input)?;
                    Ok((input, value))
                },
                |input| {
                    let input: &str = input;
                    let (input, value) = input.split_at_position_complete(
                        |c| c == ' ' || c == ','
                    )?;
                    Ok((input, value))
                },
            ))(input)?;
            let (input, _) = multispace0(input)?;
            Ok((input, (key, value)))
        }
    )(input)?;
    let (input, _) = eof(input)?;
    Ok((input, fields))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_example_4_1_1() {
        let h = SignatureHeader::parse(r#"
            keyId="rsa-key-1",algorithm="hs2019",
            created=1402170695, expires=1402170995,
            headers="(request-target) (created) (expires)
                host date digest content-length",
            signature="Base64(RSA-SHA256(signing string))"
        "#).unwrap();
        assert_eq!(h.key_id, Some("rsa-key-1"));
        assert_eq!(h.algorithm, "hs2019");
        assert_eq!(h.headers, vec![
            "(request-target)",
            "(created)", "(expires)",
            "host", "date", "digest", "content-length",
        ]);
        assert_eq!(h.signature, "Base64(RSA-SHA256(signing string))");
        assert_eq!(h.other, vec![
            ("created", "1402170695"),
            ("expires", "1402170995"),
        ]);
    }
}
