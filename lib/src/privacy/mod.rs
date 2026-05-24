//! Blob privacy: pluggable encryption schemes for realtime proposal blobs.
//!
//! Each privacy blob payload (the inner buffer carried by an EIP-4844 sidecar after
//! the existing `[version (1B)][size (3B BE)]` framing) starts with a 1-byte scheme id
//! that selects the cipher used. See `surge-taiko-mono/PRIVACY_STACK.md` for the full
//! byte-layout specification.
//!
//! Schemes:
//! - `0x00` = plaintext: payload is the compressed manifest verbatim.
//! - `0x01` = AES-256-GCM: a single shared symmetric key encrypts every Catalyst-built
//!   proposal blob with a fresh CSPRNG nonce embedded in the header.
//! - `0x02` = ECIES (secp256k1 + AES-GCM): a fresh ephemeral keypair per submission;
//!   shared secret derived via ECDH against the system's static public key, expanded
//!   to (key, nonce) via HKDF-SHA256.
//!
//! This module is `no_std`-compatible (alloc only) so it can run inside the SP1, Risc0,
//! and Zisk guest binaries.

#![allow(clippy::module_name_repetitions)]

extern crate alloc;

use alloc::vec::Vec;

pub mod aes;
pub mod ecies;

/// Plaintext (no encryption); payload is the compressed manifest verbatim.
pub const SCHEME_PLAIN: u8 = 0x00;
/// AES-256-GCM with a shared symmetric key.
pub const SCHEME_AES256_GCM: u8 = 0x01;
/// ECIES = secp256k1 ECDH ⊕ HKDF-SHA256 ⊕ AES-256-GCM.
pub const SCHEME_ECIES_SECP256K1: u8 = 0x02;

/// Errors returned by encryption/decryption helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CipherError {
    /// The blob's leading scheme byte is not recognized.
    UnknownScheme(u8),
    /// The blob is shorter than the minimum length required by its scheme header.
    Truncated,
    /// The decryption key for the blob's scheme is not configured.
    KeyMissing,
    /// The provided key bytes have the wrong length or invalid format.
    InvalidKey,
    /// AEAD authentication failed (bad key, nonce, or ciphertext tampering).
    AeadFailed,
    /// ECIES ephemeral pubkey could not be parsed.
    InvalidEphemeralPubkey,
}

/// Keys passed to `dispatch_decrypt`. Only the key required by the blob's actual scheme
/// must be `Some`; the others may be `None`.
#[derive(Default, Clone)]
pub struct DecryptKeys {
    /// Shared 32-byte AES-256-GCM key used by Catalyst's normal proposals (scheme 0x01).
    pub symmetric: Option<[u8; 32]>,
    /// 32-byte secp256k1 scalar (system FI private key, scheme 0x02).
    pub fi_private: Option<[u8; 32]>,
}

/// Decrypt a privacy blob payload (the bytes following the outer `[version][size]` frame).
///
/// Reads the leading scheme byte and dispatches to the right cipher. For scheme `0x00`
/// the remaining bytes are returned verbatim.
pub fn dispatch_decrypt(blob: &[u8], keys: &DecryptKeys) -> Result<Vec<u8>, CipherError> {
    let (scheme, rest) = blob.split_first().ok_or(CipherError::Truncated)?;
    match *scheme {
        SCHEME_PLAIN => Ok(rest.to_vec()),
        SCHEME_AES256_GCM => {
            let key = keys.symmetric.ok_or(CipherError::KeyMissing)?;
            aes::decrypt(rest, &key)
        }
        SCHEME_ECIES_SECP256K1 => {
            let sk = keys.fi_private.ok_or(CipherError::KeyMissing)?;
            ecies::decrypt(rest, &sk)
        }
        other => Err(CipherError::UnknownScheme(other)),
    }
}

/// HKDF-SHA256 info string for ECIES key/nonce derivation (scheme 0x02).
///
/// Both submitter and system MUST use this exact byte string to derive matching
/// `(K_eph, nonce_eph)` from the ECDH shared secret.
pub const ECIES_INFO: &[u8] = b"surge-fi-v1";

/// Computes keccak256 of the input. Used in the guest to bind the witness-supplied
/// privacy keys to compile-time hashes baked via `build.rs` — this means the proof's
/// vkey commits to the keys without committing the secret bytes in the public input.
pub fn keccak256_32(input: &[u8]) -> [u8; 32] {
    use tiny_keccak::{Hasher, Keccak};
    let mut hasher = Keccak::v256();
    hasher.update(input);
    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    out
}

/// Asserts that `keccak256(key) == expected_hash`. Returns `Err(InvalidKey)` on mismatch.
/// Use in guest code to verify a witness-supplied key matches the compile-time hash.
pub fn assert_key_hash(key: &[u8; 32], expected_hash: &[u8; 32]) -> Result<(), CipherError> {
    if &keccak256_32(key) == expected_hash {
        Ok(())
    } else {
        Err(CipherError::InvalidKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatch_plaintext() {
        let payload = [0x00u8, b'h', b'i'];
        let out = dispatch_decrypt(&payload, &DecryptKeys::default()).unwrap();
        assert_eq!(out, b"hi");
    }

    #[test]
    fn dispatch_unknown_scheme() {
        let payload = [0xFFu8, 0xAA];
        let err = dispatch_decrypt(&payload, &DecryptKeys::default()).unwrap_err();
        assert_eq!(err, CipherError::UnknownScheme(0xFF));
    }

    #[test]
    fn dispatch_aes_missing_key() {
        let payload = [SCHEME_AES256_GCM, 0u8];
        let err = dispatch_decrypt(&payload, &DecryptKeys::default()).unwrap_err();
        assert_eq!(err, CipherError::KeyMissing);
    }

    #[test]
    fn dispatch_truncated_blob() {
        let payload: [u8; 0] = [];
        let err = dispatch_decrypt(&payload, &DecryptKeys::default()).unwrap_err();
        assert_eq!(err, CipherError::Truncated);
    }
}
