# bronco

Bronco provides authenticated and encrypted API tokens.

Based on the [Branca] specification (with slight alterations) this module provides authenticated
and encrypted API tokens. Crypto primitives are provided by [libsodium] via the [`sodiumoxide`] library.

IETF XChaCha20-Poly1305 AEAD symmetric encryption is used to create the tokens. The encrypted token
is base64-encoded, using the [url-safe Base64 variant][Base64] (without padding). Branca uses Base62 to ensure
url safety, but since the url-safe variant of Base64 encoding is more common, we use that instead.

## Security Guarantees

I provide **absolutely no security guarantees whatsoever**.

I am not a cryptographer. This is not an audited implementation.
This does not follow the Branca specification 100%.

This a library I wrote to better understand AEAD primitives and authenticated/encrypted API tokens.
I _do_ use it in my own project, [pasta6] knowing full well that I probably made some trivial mistakes.

## Example

Add `bronco` and `sodiumoxide` to your dependencies:

```toml
bronco = "0.1.0"
sodiumoxide = "0.2.6"
```

### Encoding

```rust
use bronco::encode;
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf::gen_key;

sodiumoxide::init();

let key = gen_key();
let message: &str = "hello, world!";
let token: String = encode(message, key.as_ref()).unwrap();
```

### Decoding

```rust
use bronco::decode;

// let token: &str = ...;
// let key: &[u8] = ...;
let ttl: u32 = 60; // token is valid for 1 minute
let message = decode(token, key, ttl).unwrap();
assert_eq!(message, "hello, world!");
```

## Token Format

Tokens have a header, ciphertext, and authentication tag.
The header has a version, timestamp, and nonce.
Overall the token structure is:

```rust
Version (1B) || Timestamp (4B) || Nonce (24B) || Ciphertext (*B) || Tag (16B)
```

The ciphertext can be arbitrarily long, and will be exactly the length of the plaintext message.

The string representation of the binary token uses [Base64 (URL-safe variant)][Base64] encoding, with the following
character set:

```rust
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_
```

More details can be found in the [Branca specification].

## Keys

Keys **must** be 32 bytes in length.
Any 32 byte slice can be used as a key, but it is **highly recommended** you use sodiumoxide's
[`sodiumoxide::crypto::aead::xchacha20poly1305_ietf::gen_key`] function to generate truly random keys.

## Implementation Details

This module has several significant changes from the Branca specification.

First, the binary token is encoded as a string using [Base64 (URL-safe variant)][Base64], not Base62.

Second, token payloads are assumed to be valid UTF-8. This module only allows encoding of
valid UTF-8 strings, so this should never be a problem. A custom implementation could allow
the encoding of arbitrary bytes into a token, so to handle non UTF-8 payloads we do a lossy
UTF-8 conversion when parsing the payload. Invalid characters are replaced with the UTF-8
replacement character.

TTL is enforced for tokens, unless set to `0` at decoding time.
When a token's timestamp is more than `ttl` seconds in the past,
it is treated as a decoding error. It is not possible to specify an infinite TTL, but
you can set arbitrarily large `u32` values.

**NOTE**: TTLs which result in an integer overflow when added to the UNIX epoch timestamp are
  treated as invalid.

[Branca]: https://branca.io/
[Branca specification]: https://github.com/tuupola/branca-spec
[libsodium]: https://github.com/jedisct1/libsodium
[`sodiumoxide`]: https://github.com/sodiumoxide/sodiumoxide
[`sodiumoxide::crypto::aead::xchacha20poly1305_ietf::gen_key`]: https://docs.rs/sodiumoxide/0.2.6/sodiumoxide/crypto/aead/xchacha20poly1305_ietf/fn.gen_key.html
[pasta6]: https://github.com/indiv0/pasta6
[Base64]: https://tools.ietf.org/html/rfc4648#section-5

License: GPL-3.0-or-later
