# sigh!

This crate supplies everything for dealing with [HTTP
signatures](https://datatracker.ietf.org/doc/html/draft-cavage-http-signatures-12)
in ActivityPub:

- Keypair generation
- Signing
- Verification

See the [documentation](https://docs.rs/sigh) for usage examples.

The [OpenSSL crate](https://crates.io/crates/openssl) is used for
cryptographic algorithms. The [http
crate](https://crates.io/crates/http) is used as a common denominator
interface for many HTTP client and server implementations.

Beware that you *must also* take care of `Digest:` headers, using
eg. [http-digest-headers](https://github.com/dskyberg/http_digest_headers).

## Supported algorithms

| Algorithm                 | Implemented | Used by... |
|---------------------------|-------------|------------|
| `hs2019` (Ed25519-SHA512) | ✓           |            |
| `rsa-sha1`                |             |            |
| `rsa-sha256`              | ✓           | Mastodon   |
| `hmac-sha256`             |             |            |
| `ecdsa-sha256`            |             |            |
