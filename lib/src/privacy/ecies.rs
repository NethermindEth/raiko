//! ECIES cipher (scheme 0x02): secp256k1 ECDH ⊕ HKDF-SHA256 ⊕ AES-256-GCM.
//!
//! Used for forced-inclusion blobs in privacy mode. The submitter encrypts the
//! compressed manifest `M` to the system's static public key `PK_sys`; only holders
//! of the corresponding private key `SK_sys` can decrypt.
//!
//! Blob layout (after the leading 0x02 scheme byte the dispatcher strips):
//!
//! ```text
//! [ pk_eph (33B compressed secp256k1) ] [ ciphertext (len(M)) ] [ tag (16B) ]
//! ```
//!
//! The AES-GCM nonce is NOT carried on the wire — both sides derive it from the
//! ECDH shared secret via HKDF-SHA256, alongside the AES key. See `super::ECIES_INFO`.
//!
//! Submitter side:
//! 1. Draw ephemeral `(sk_eph, pk_eph)` on secp256k1 from a CSPRNG.
//! 2. `s = ECDH(sk_eph, PK_sys)`.
//! 3. `(K_eph || nonce_eph) = HKDF-SHA256(salt=∅, ikm=s, info="surge-fi-v1", L=44)`.
//! 4. `C || tag = AES-256-GCM(K_eph, nonce_eph, M, aad=∅)`.
//! 5. Emit `[pk_eph || C || tag]`; discard `sk_eph`.
//!
//! System side reverses with `s = ECDH(SK_sys, pk_eph)`.

extern crate alloc;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use alloc::vec::Vec;
use hkdf::Hkdf;
use k256::ecdh::diffie_hellman;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{NonZeroScalar, PublicKey, SecretKey};
use sha2::Sha256;

use super::{CipherError, ECIES_INFO};

/// Length of a compressed secp256k1 pubkey in bytes (header + 32-byte x-coord).
pub const PK_LEN: usize = 33;
/// Length of an AES-256 key in bytes.
pub const KEY_LEN: usize = 32;
/// Length of the AES-GCM nonce in bytes.
pub const NONCE_LEN: usize = 12;
/// Length of the AES-GCM authentication tag in bytes.
pub const TAG_LEN: usize = 16;
/// HKDF output length (key + nonce concatenated).
const HKDF_LEN: usize = KEY_LEN + NONCE_LEN;
/// Minimum length of a scheme-0x02 inner payload.
pub const MIN_INNER_LEN: usize = PK_LEN + TAG_LEN;

/// Encrypts `plaintext` to the system pubkey `system_pk` using the supplied ephemeral
/// private key `sk_eph`. Returns the scheme-0x02 *inner* payload `[pk_eph || ct || tag]`
/// (without the leading scheme byte).
///
/// In production, callers MUST generate `sk_eph` from a CSPRNG and never reuse it.
/// This function is exposed primarily for tests; off-system FI submitters typically
/// use a separate CLI / library to perform the encrypt step before broadcasting their
/// blob tx.
pub fn encrypt(
    plaintext: &[u8],
    system_pk: &[u8; PK_LEN],
    sk_eph: &[u8; 32],
) -> Result<Vec<u8>, CipherError> {
    let recipient = PublicKey::from_sec1_bytes(system_pk).map_err(|_| CipherError::InvalidKey)?;
    let secret = SecretKey::from_slice(&sk_eph[..]).map_err(|_| CipherError::InvalidKey)?;
    let scalar = NonZeroScalar::from(&secret);

    // pk_eph = sk_eph * G (compressed for the wire)
    let pk_eph = secret.public_key();
    let pk_eph_bytes = pk_eph.to_encoded_point(true);
    debug_assert_eq!(pk_eph_bytes.as_bytes().len(), PK_LEN);

    // ECDH: s = sk_eph * PK_sys
    let shared = diffie_hellman(scalar, recipient.as_affine());
    let ikm = shared.raw_secret_bytes();

    let (k_eph, nonce_eph) = derive_key_and_nonce(ikm.as_slice())?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&k_eph));
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce_eph),
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|_| CipherError::AeadFailed)?;

    let mut out = Vec::with_capacity(PK_LEN + ct.len());
    out.extend_from_slice(pk_eph_bytes.as_bytes());
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Decrypts a scheme-0x02 inner payload `[pk_eph || ct || tag]` using the system
/// private key `sk_sys`. Returns the plaintext compressed manifest.
pub fn decrypt(inner: &[u8], sk_sys: &[u8; 32]) -> Result<Vec<u8>, CipherError> {
    if inner.len() < MIN_INNER_LEN {
        return Err(CipherError::Truncated);
    }
    let (pk_eph_bytes, ct_and_tag) = inner.split_at(PK_LEN);

    let pk_eph = PublicKey::from_sec1_bytes(pk_eph_bytes)
        .map_err(|_| CipherError::InvalidEphemeralPubkey)?;
    let secret = SecretKey::from_slice(&sk_sys[..]).map_err(|_| CipherError::InvalidKey)?;
    let scalar = NonZeroScalar::from(&secret);

    let shared = diffie_hellman(scalar, pk_eph.as_affine());
    let ikm = shared.raw_secret_bytes();

    let (k_eph, nonce_eph) = derive_key_and_nonce(ikm.as_slice())?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&k_eph));
    cipher
        .decrypt(
            Nonce::from_slice(&nonce_eph),
            Payload {
                msg: ct_and_tag,
                aad: &[],
            },
        )
        .map_err(|_| CipherError::AeadFailed)
}

/// HKDF-SHA256(salt=∅, ikm=shared_secret, info=`super::ECIES_INFO`, L=44 bytes).
/// First 32 bytes are the AES-256 key; next 12 bytes are the AES-GCM nonce.
fn derive_key_and_nonce(ikm: &[u8]) -> Result<([u8; KEY_LEN], [u8; NONCE_LEN]), CipherError> {
    let mut out = [0u8; HKDF_LEN];
    let hk = Hkdf::<Sha256>::new(None, ikm);
    hk.expand(ECIES_INFO, &mut out)
        .map_err(|_| CipherError::AeadFailed)?;

    let mut key = [0u8; KEY_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    key.copy_from_slice(&out[..KEY_LEN]);
    nonce.copy_from_slice(&out[KEY_LEN..]);
    Ok((key, nonce))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::SecretKey;

    fn make_keypair(seed: u8) -> ([u8; 32], [u8; PK_LEN]) {
        let sk_bytes = [seed; 32];
        let sk = SecretKey::from_slice(&sk_bytes).unwrap();
        let pk = sk.public_key();
        let pk_bytes = pk.to_encoded_point(true);
        let mut pk_arr = [0u8; PK_LEN];
        pk_arr.copy_from_slice(pk_bytes.as_bytes());
        (sk_bytes, pk_arr)
    }

    #[test]
    fn roundtrip() {
        let (sk_sys, pk_sys) = make_keypair(0x11);
        let (sk_eph, _pk_eph) = make_keypair(0x22);

        let m = b"forced inclusion plaintext payload";
        let inner = encrypt(m, &pk_sys, &sk_eph).unwrap();

        // First 33 bytes are pk_eph, the rest is ct + tag.
        assert!(inner.len() >= PK_LEN + TAG_LEN);
        assert_eq!(inner.len(), PK_LEN + m.len() + TAG_LEN);

        let pt = decrypt(&inner, &sk_sys).unwrap();
        assert_eq!(pt, m);
    }

    #[test]
    fn wrong_recipient_fails() {
        let (_sk_sys, pk_sys) = make_keypair(0x11);
        let (sk_eph, _) = make_keypair(0x22);

        let inner = encrypt(b"x", &pk_sys, &sk_eph).unwrap();

        let (sk_other, _) = make_keypair(0x33);
        assert_eq!(decrypt(&inner, &sk_other).unwrap_err(), CipherError::AeadFailed);
    }

    #[test]
    fn tampered_ct_fails() {
        let (sk_sys, pk_sys) = make_keypair(0x11);
        let (sk_eph, _) = make_keypair(0x22);

        let mut inner = encrypt(b"abcdef", &pk_sys, &sk_eph).unwrap();
        // Flip a byte in the ciphertext (after the 33-byte pk_eph).
        inner[PK_LEN + 1] ^= 0x01;
        assert_eq!(decrypt(&inner, &sk_sys).unwrap_err(), CipherError::AeadFailed);
    }

    #[test]
    fn truncated_inner_fails() {
        let inner = [0u8; MIN_INNER_LEN - 1];
        let sk = [0x11u8; 32];
        assert_eq!(decrypt(&inner, &sk).unwrap_err(), CipherError::Truncated);
    }

    #[test]
    fn invalid_pk_eph_fails() {
        let mut inner = [0u8; PK_LEN + TAG_LEN + 1];
        // Make the first byte an invalid SEC1 prefix and zero the rest.
        inner[0] = 0xFF;
        let sk = [0x11u8; 32];
        let err = decrypt(&inner, &sk).unwrap_err();
        assert_eq!(err, CipherError::InvalidEphemeralPubkey);
    }
}
