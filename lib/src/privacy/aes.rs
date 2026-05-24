//! AES-256-GCM cipher (scheme 0x01).
//!
//! Blob layout (the bytes after the leading 0x01 scheme byte that the dispatcher strips):
//!
//! ```text
//! [ nonce (12B) ] [ ciphertext (len(M) bytes) ] [ tag (16B) ]
//! ```
//!
//! `M` is the compressed manifest, identical to what would have been the inner blob
//! payload in non-privacy mode. AES-GCM is a stream-cipher mode so `len(ciphertext) == len(M)`.

extern crate alloc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use alloc::vec::Vec;

use super::CipherError;

/// Length of the AES-256 key in bytes.
pub const KEY_LEN: usize = 32;
/// Length of the AES-GCM nonce in bytes (96-bit).
pub const NONCE_LEN: usize = 12;
/// Length of the AES-GCM authentication tag in bytes.
pub const TAG_LEN: usize = 16;
/// Minimum length of a scheme-0x01 inner payload (just the header fields, no plaintext).
pub const MIN_INNER_LEN: usize = NONCE_LEN + TAG_LEN;

/// Encrypts `plaintext` with AES-256-GCM under `key` and `nonce`, returning the
/// scheme-0x01 *inner* payload `[nonce || ciphertext || tag]` (without the leading
/// scheme byte — callers prepend it).
///
/// `nonce` MUST come from a CSPRNG and never be reused with the same key.
pub fn encrypt(
    plaintext: &[u8],
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, CipherError> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|_| CipherError::AeadFailed)?;

    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypts a scheme-0x01 inner payload `[nonce || ciphertext || tag]`.
///
/// The returned bytes are the plaintext compressed manifest `M`, unchanged in length
/// from the encryption call's input.
pub fn decrypt(inner: &[u8], key: &[u8; KEY_LEN]) -> Result<Vec<u8>, CipherError> {
    if inner.len() < MIN_INNER_LEN {
        return Err(CipherError::Truncated);
    }
    let (nonce, ct_and_tag) = inner.split_at(NONCE_LEN);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ct_and_tag,
                aad: &[],
            },
        )
        .map_err(|_| CipherError::AeadFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x42u8; 32];
    const NONCE: [u8; 12] = [0x37u8; 12];

    #[test]
    fn roundtrip() {
        let m = b"hello realtime privacy";
        let inner = encrypt(m, &KEY, &NONCE).unwrap();

        // Layout: nonce (12) + ct (len(m)) + tag (16)
        assert_eq!(inner.len(), 12 + m.len() + 16);
        assert_eq!(&inner[..12], &NONCE);

        let pt = decrypt(&inner, &KEY).unwrap();
        assert_eq!(pt, m);
    }

    #[test]
    fn empty_plaintext_roundtrip() {
        let m: &[u8] = b"";
        let inner = encrypt(m, &KEY, &NONCE).unwrap();
        assert_eq!(inner.len(), 12 + 16);

        let pt = decrypt(&inner, &KEY).unwrap();
        assert_eq!(pt, m);
    }

    #[test]
    fn tampered_ciphertext_fails() {
        let inner = encrypt(b"abcdef", &KEY, &NONCE).unwrap();
        let mut bad = inner.clone();
        // Flip one byte of the ciphertext (after the 12-byte nonce, before the tag).
        bad[14] ^= 0x01;
        assert_eq!(decrypt(&bad, &KEY).unwrap_err(), CipherError::AeadFailed);
    }

    #[test]
    fn wrong_key_fails() {
        let inner = encrypt(b"abc", &KEY, &NONCE).unwrap();
        let other = [0x99u8; 32];
        assert_eq!(decrypt(&inner, &other).unwrap_err(), CipherError::AeadFailed);
    }

    #[test]
    fn truncated_inner_fails() {
        let inner = [0u8; MIN_INNER_LEN - 1];
        assert_eq!(decrypt(&inner, &KEY).unwrap_err(), CipherError::Truncated);
    }
}
