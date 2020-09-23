//! Bronco provides authenticated and encrypted API tokens.
//!
//! Based on the [Branca] specification (with slight alterations) this module provides authenticated
//! and encrypted API tokens. Crypto primitives are provided by [libsodium] via the [`sodiumoxide`] library.
//!
//! IETF XChaCha20-Poly1305 AEAD symmetric encryption is used to create the tokens. The encrypted token
//! is base64-encoded, using the [url-safe Base64 variant][Base64] (without padding). Branca uses Base62 to ensure
//! url safety, but since the url-safe variant of Base64 encoding is more common, we use that instead.
//!
//! # Security Guarantees
//!
//! I provide **absolutely no security guarantees whatsoever**.
//!
//! I am not a cryptographer. This is not an audited implementation.
//! This does not follow the Branca specification 100%.
//!
//! This a library I wrote to better understand AEAD primitives and authenticated/encrypted API tokens.
//! I _do_ use it in my own project, [pasta6] knowing full well that I probably made some trivial mistakes.
//!
//! # Example
//!
//! Add `bronco` and `sodiumoxide` to your dependencies:
//!
//! ```toml
//! bronco = "0.1.0"
//! sodiumoxide = "0.2.6"
//! ```
//!
//! ## Encoding
//!
//! ```rust
//! use bronco::encode;
//! use sodiumoxide::crypto::aead::xchacha20poly1305_ietf::gen_key;
//!
//! sodiumoxide::init();
//!
//! let key = gen_key();
//! let message: &str = "hello, world!";
//! let token: String = encode(message, key.as_ref()).unwrap();
//! ```
//!
//! ## Decoding
//!
//! ```rust
//! # use bronco::encode;
//! use bronco::decode;
//!
//! # let key = sodiumoxide::crypto::aead::xchacha20poly1305_ietf::gen_key();
//! # let key: &[u8] = key.as_ref();
//! # let token = encode("hello, world!", key.as_ref()).unwrap();
//! # let token: &str = token.as_ref();
//! // let token: &str = ...;
//! // let key: &[u8] = ...;
//! let ttl: u32 = 60; // token is valid for 1 minute
//! let message = decode(token, key, ttl).unwrap();
//! assert_eq!(message, "hello, world!");
//! ```
//!
//! # Token Format
//!
//! Tokens have a header, ciphertext, and authentication tag.
//! The header has a version, timestamp, and nonce.
//! Overall the token structure is:
//!
//! ```ignore
//! Version (1B) || Timestamp (4B) || Nonce (24B) || Ciphertext (*B) || Tag (16B)
//! ```
//!
//! The ciphertext can be arbitrarily long, and will be exactly the length of the plaintext message.
//!
//! The string representation of the binary token uses [Base64 (URL-safe variant)][Base64] encoding, with the following
//! character set:
//!
//! ```ignore
//! ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_
//! ```
//!
//! More details can be found in the [Branca specification].
//!
//! # Keys
//!
//! Keys **must** be 32 bytes in length.
//! Any 32 byte slice can be used as a key, but it is **highly recommended** you use sodiumoxide's
//! [`sodiumoxide::crypto::aead::xchacha20poly1305_ietf::gen_key`] function to generate truly random keys.
//!
//! # Implementation Details
//!
//! This module has several significant from the Branca specification.
//!
//! First, the binary token is encoded as a string using [Base64 (URL-safe variant)][Base64], not Base62.
//!
//! Second, token payloads are assumed to be valid UTF-8. This module only allows encoding of
//! valid UTF-8 strings, so this should never be a problem. A custom implementation could allow
//! the encoding of arbitrary bytes into a token, so to handle non UTF-8 payloads we do a lossy
//! UTF-8 conversion when parsing the payload. Invalid characters are replaced with the UTF-8
//! replacement character.
//!
//! TTL is enforced for tokens, unless set to `0` at decoding time.
//! When a token's timestamp is more than `ttl` seconds in the past,
//! it is treated as a decoding error. It is not possible to specify an infinite TTL, but
//! you can set arbitrarily large `u32` values.
//!
//! **NOTE**: TTLs which result in an integer overflow when added to the UNIX epoch timestamp are
//!   treated as invalid.
//!
//! [Branca]: https://branca.io/
//! [Branca specification]: https://github.com/tuupola/branca-spec
//! [libsodium]: https://github.com/jedisct1/libsodium
//! [`sodiumoxide`]: https://github.com/sodiumoxide/sodiumoxide
//! [`sodiumoxide::crypto::aead::xchacha20poly1305_ietf::gen_key`]: https://docs.rs/sodiumoxide/0.2.6/sodiumoxide/crypto/aead/xchacha20poly1305_ietf/fn.gen_key.html
//! [pasta6]: https://github.com/indiv0/pasta6
//! [Base64]: https://tools.ietf.org/html/rfc4648#section-5
#[cfg(test)]
#[macro_use]
extern crate assert_matches;

use self::DecodeError::{
    Base64DecodeFailed, InvalidVersion, TokenExpired, TokenTooShort, TtlTooLarge,
    VerificationFailed,
};

use std::time::SystemTime;

use base64::URL_SAFE_NO_PAD;
use byteorder::{BigEndian, ByteOrder};
use sodiumoxide::crypto::aead::xchacha20poly1305_ietf::{gen_nonce, open, seal, Key, Nonce};

const VERSION: u8 = 0x01;

// Lengths of fixed-size components in the token.
const HEADER_LEN: usize = 29; // 1 byte version + 4 byte timestamp + 24 byte nonce
const TAG_LEN: usize = 16; // 16 byte poly1305 tag

// Offsets for token components, based on the lengths of the preceding components.
const TIMESTAMP_OFFSET: usize = 1; // Timestamp comes after 1 byte version.
const NONCE_OFFSET: usize = 5; // Nonce comes after 1 byte version and 4 byte timestamp.

// Minimum token length is version + timestamp + nonce + ciphertext + tag = 1 + 4 + 24 + 0 + 16 = 45 bytes.
const MIN_TOKEN_LENGTH: usize = 45;
// Each character in Base64 is used to represent 6 bits (`log_2(64) = 6`).
// To represent `n` bytes we need `4*(n/3)` chars, and this needs to be rounded up to a multiple of 4.
// So to represent a (minimum length) 45-byte token we need `4*(45/3) = 60 chars`.
const MIN_ENCODED_LENGTH: usize = 60;

#[derive(Debug, PartialEq)]
pub enum EncodeError {
    /// Key of wrong length (too short or too long) was provided.
    WrongKeyLength,
}

#[derive(Debug, PartialEq)]
pub enum DecodeError {
    /// Key of wrong length (too short or too long) was provided.
    WrongKeyLength,
    /// Failed to Base64 decode provided token.
    Base64DecodeFailed(base64::DecodeError),
    /// Token provided for decoding is too short (less than 45 bytes).
    TokenTooShort,
    /// Verification of authenticated ciphertext failed.
    VerificationFailed,
    /// TTL provided during verification resulted in a expiration date too far into the future (after 06:28:15 UTC on Sunday, 7 February 2106).
    TtlTooLarge,
    /// Decoded token's timestamp is more than TTL seconds in the past.
    TokenExpired,
    /// Decoded token's version is invalid or not supported by the library.
    InvalidVersion,
}

/// Encodes an arbitrary `message` into a token, given a 256 bit (i.e. 32 byte) secret key.
///
/// `message` - data to be encoded as a Bronco token.
///
/// `key` - 32 byte secret key.
///
/// Encoding is done by performing the following steps, in order:
/// 1. Use the current UNIX timestamp as `timestamp`.
/// 2. Generate a 24 byte cryptographically secure `nonce`.
/// 3. Construct the `header` by concatenating a `version` byte (currently always `0x01`), `timestamp` (big-endian), and `nonce`
/// 4. Encrypt the payload with IETF XChaCha20-Poly1305 AEAD with the secret `key`. Use `header` as the additional data for AEAD.
/// 5. Concatenate `header`, and the `ciphertext|tag` result of step 4.
/// 6. [Base64 (URL-safe variant)][Base64] encode the entire token, without padding.
///
/// # Example
/// ```rust
/// use bronco::encode;
/// use sodiumoxide::crypto::aead::xchacha20poly1305_ietf::gen_key;
///
/// let key = gen_key();
/// let message: &str = "hello, world!";
/// let token: String = encode(message, key.as_ref()).unwrap();
/// ```
///
/// # Errors
///
/// Returns [`WrongKeyLength`] if the key is not exactly 32 bytes.
///
/// # Panics
///
/// Panics if the current system time is before UNIX epoch (due to anomalies such as the
/// system clock being adjusted backwards).
///
/// [`WrongKeyLength`]: enum.EncodeError.html#variant.WrongKeyLength
/// [Base64]: https://tools.ietf.org/html/rfc4648#section-5
pub fn encode(message: &str, key: &[u8]) -> Result<String, EncodeError> {
    let timestamp = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("failed to get timestamp from system time")
        .as_secs() as u32;

    encode_with_timestamp(message.as_ref(), key, timestamp)
}

fn encode_with_timestamp(
    message: &[u8],
    key: &[u8],
    timestamp: u32,
) -> Result<String, EncodeError> {
    let key = Key::from_slice(key).ok_or(EncodeError::WrongKeyLength)?;

    // Generate a unique nonce.
    let nonce = gen_nonce();

    // Version || Timestamp || Nonce
    let mut header = [0u8; HEADER_LEN];
    header[0] = VERSION;
    BigEndian::write_u32(&mut header[TIMESTAMP_OFFSET..NONCE_OFFSET], timestamp);
    header[NONCE_OFFSET..].copy_from_slice(nonce.as_ref());

    // Encrypt and authenticate the message, returning the ciphertext of the message appended with the tag.
    let ciphertext_and_tag = seal(&message, Some(&header), &nonce, &key);

    // Combine the header, ciphertext, and tag.
    let mut token = vec![0u8; HEADER_LEN + ciphertext_and_tag.len()];
    assert!(token.len() >= MIN_TOKEN_LENGTH);
    assert_eq!(token.len(), HEADER_LEN + message.len() + TAG_LEN);
    token[..HEADER_LEN].copy_from_slice(header.as_ref());
    token[HEADER_LEN..].copy_from_slice(ciphertext_and_tag.as_ref());

    // Encode the token with URL-safe Base64.
    let encoded = base64::encode_config(token, URL_SAFE_NO_PAD);
    assert!(encoded.len() >= MIN_ENCODED_LENGTH);

    Ok(encoded)
}

/// Decodes a Bronco `token` to a string payload, given a 256 bit (i.e. 32 byte) secret key.
///
/// `token` - Bronco token to be decoded to a string.
///
/// `key` - 32 byte secret key.
///
/// `ttl` - TTL in seconds, used to treat the token as expired if has a `timestamp` more than TTL seconds in the past.
/// If `ttl` is `0`, the check is not performed.
///
/// Decoding is done by performing the following steps, in order:
/// 1. Verify that `token` is at least 60 characters long.
/// 2. [Base64 (URL-safe variant)][Base64] decode `token`.
/// 3. Verify that `version` (the first byte of the decoded token) is `0x01`.
/// 4. Extract the `header` (the first 29 bytes) from the decoded token.
/// 5. Extract the `nonce` (the last 24 bytes of `header) from the header.
/// 6. Decrypt and verify the `ciphertext|tag` combination with IETF XChaCha20-Poly1305 AEAD using the secret `key` and `nonce`.
///   `header` is used as the additional data.
/// 7. Extract `timestamp` (bytes 2 to 5) from `header`.
/// 8. Verify that `timestamp` is less than `ttl` seconds in the past (if `ttl` is greater than `0`).
///
/// # Example
/// ```rust
/// # use bronco::encode;
/// # use sodiumoxide::crypto::aead::xchacha20poly1305_ietf::gen_key;
/// use bronco::decode;
///
/// # let key = gen_key();
/// # let key: &[u8] = key.as_ref();
/// # let token = encode("hello, world!", key).unwrap();
/// # let token = token.as_ref();
/// // let key: &[u8] = ...;
/// // let token: &str = ...;
/// let ttl = 60; // token expires 1 minute after creation
/// let message: String = decode(token, key, ttl).unwrap();
/// assert_eq!(message, "hello, world!");
/// ```
///
/// # Errors
///
/// Returns [`TokenTooShort`] if the token is less than 60 characters long (minimum length of an encoded Bronco token).
///
/// Returns [`WrongKeyLength`] if the key is not exactly 32 bytes.
///
/// Returns [`Base64DecodeFailed`] if the token could not be Base64 decoded.
///
/// Returns [`InvalidVersion`] if the `version` byte of the token is not equal to `0x01`.
///
/// Returns [`VerificationFailed`] if the `ciphertext|tag` pair could not be decrypted and verified.
///
/// Returns [`TtlTooLarge`] if the current UNIX timestamp + `ttl` seconds is too far in the future.
///
/// # Panics
///
/// Panics if the current system time is before UNIX epoch (due to anomalies such as the
/// system clock being adjusted backwards).
///
/// [`TokenTooShort`]: enum.DecodeError.html#variant.TokenTooShort
/// [`Base64DecodeFailed`]: enum.DecodeError.html#variant.Base64DecodeFailed
/// [`InvalidVersion`]: enum.DecodeError.html#variant.InvalidVersion
/// [`VerificationFailed`]: enum.DecodeError.html#variant.VerificationFailed
/// [`TtlTooLarge`]: enum.DecodeError.html#variant.TtlTooLarge
/// [`WrongKeyLength`]: enum.DecodeError.html#variant.WrongKeyLength
/// [Base64]: https://tools.ietf.org/html/rfc4648#section-5
pub fn decode(token: &str, key: &[u8], ttl: u32) -> Result<String, DecodeError> {
    let message = decode_bytes(token, key, ttl)?;
    Ok(String::from_utf8_lossy(&message).into())
}

fn decode_bytes(token: &str, key: &[u8], ttl: u32) -> Result<Vec<u8>, DecodeError> {
    if token.len() < MIN_ENCODED_LENGTH {
        return Err(TokenTooShort);
    }

    let key = Key::from_slice(key).ok_or(DecodeError::WrongKeyLength)?;

    // Decode the token from URL-safe Base64.
    let token = base64::decode_config(token, URL_SAFE_NO_PAD).map_err(Base64DecodeFailed)?;
    assert!(token.len() >= MIN_TOKEN_LENGTH);

    // Check that the token is a version we support.
    if token[0] != VERSION {
        return Err(InvalidVersion);
    }

    // Extract the header of the token (the prefix) and the nonce from the header (trailing 24 bytes of the header).
    let header = &token[..HEADER_LEN];
    let nonce = Nonce::from_slice(&header[NONCE_OFFSET..]).unwrap();

    // Decrypt and authenticate the message.
    let plaintext =
        open(&token[HEADER_LEN..], Some(header), &nonce, &key).map_err(|_| VerificationFailed)?;

    if ttl != 0 {
        // Extract the timestamp from the header.
        let timestamp = BigEndian::read_u32(&header[TIMESTAMP_OFFSET..NONCE_OFFSET]);

        // Check if the token has expired.
        let expiration = timestamp.checked_add(ttl).ok_or(TtlTooLarge)? as u64;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("failed to get timestamp from system time")
            .as_secs();
        if expiration < now {
            return Err(TokenExpired);
        }
    }

    Ok(plaintext)
}

#[cfg(test)]
mod test {
    use super::*;
    use sodiumoxide::crypto::aead::xchacha20poly1305_ietf::gen_key;
    use std::{str, thread, time::Duration};

    #[test]
    fn test_crypto() {
        let message = "hello, world!";
        let key = gen_key();

        // Empty key should error.
        assert_eq!(encode(message, &[]), Err(EncodeError::WrongKeyLength));

        // Empty token should be 60 chars in length when encoded.
        let token = encode("", key.as_ref()).unwrap();
        assert_eq!(token.len(), 60);

        // A token 59 chars in length should be too short.
        assert_eq!(
            decode(str::from_utf8(&['a' as u8; 59]).unwrap(), key.as_ref(), 0),
            Err(TokenTooShort)
        );

        // A sufficient length token that isn't valid Base64 should return an error.
        assert_matches!(
            decode(str::from_utf8(&[0; 60]).unwrap(), key.as_ref(), 0),
            Err(Base64DecodeFailed(_))
        );

        // A TTL of 1 should result in the token expiring after 2 seconds.
        thread::sleep(Duration::from_secs(2));
        assert_eq!(decode(&token, key.as_ref(), 1), Err(TokenExpired));

        // A TTL of 0 should result in the token not expiring.
        assert_eq!(decode(&token, key.as_ref(), 0), Ok("".to_owned()));

        // A too-large TTL should result in an error.
        assert_eq!(
            decode(&token, key.as_ref(), std::u32::MAX),
            Err(TtlTooLarge)
        );
    }
}
