use anyhow::Result;
use raiko_lib::primitives::{Address, B256};
use sha3::{Digest, Keccak256};

pub fn get_address_from_private_key(private_key: &secp256k1::SecretKey) -> Result<Address> {
    let secp = secp256k1::Secp256k1::new();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, private_key);

    let public_key_bytes = &public_key.serialize_uncompressed()[1..];
    let hash = Keccak256::digest(public_key_bytes);

    Ok(Address::from_slice(&hash[12..]))
}

pub fn sign_message(private_key: &secp256k1::SecretKey, message: &B256) -> Result<[u8; 65]> {
    let secp = secp256k1::Secp256k1::new();
    let message = secp256k1::Message::from_digest_slice(message.as_slice())?;
    let sig = secp.sign_ecdsa_recoverable(&message, private_key);

    let (recovery_id, sig_bytes) = sig.serialize_compact();
    let mut signature = [0u8; 65];
    signature[..64].copy_from_slice(&sig_bytes);
    signature[64] = recovery_id.to_i32() as u8 + 27; // Add 27 for Ethereum compatibility

    Ok(signature)
}

pub fn recover_signer_unchecked(sig: &[u8; 65], msg: &B256) -> Result<Address> {
    use secp256k1::{
        ecdsa::{RecoverableSignature, RecoveryId},
        Message,
    };

    let sig = RecoverableSignature::from_compact(
        &sig[0..64],
        RecoveryId::from_i32((sig[64] as i32) - 27)?,
    )?;

    let secp = secp256k1::Secp256k1::new();
    let message = Message::from_digest_slice(msg.as_slice())?;
    let public_key = secp.recover_ecdsa(&message, &sig)?;

    // Convert public key to Ethereum address
    let public_key_bytes = public_key.serialize_uncompressed();
    let hash = Keccak256::digest(&public_key_bytes[1..]); // Skip the 0x04 prefix

    Ok(Address::from_slice(&hash[12..]))
}
