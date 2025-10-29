use alloy_primitives::{Bytes, B256, U256};
use alloy_rlp::{Buf, Decodable, Header as RlpHeader};
use alloy_trie::{proof::verify_proof, Nibbles};
use anyhow::{bail, Context, Result};
use taiko_reth::evm::precompiles::l1sload::{clear_l1_storage_cache, set_l1_storage_value};
use tracing::info;

use crate::input::L1StorageProof;
use crate::primitives::keccak::keccak;

/// Verify and populate L1SLOAD cache with storage values before EVM execution
pub fn verify_and_populate_l1sload_proofs(
    l1_storage_proofs: &[L1StorageProof],
    anchor_state_root: B256,
) -> Result<()> {
    for (i, proof) in l1_storage_proofs.iter().enumerate() {
        // Verify L1 storage proof against anchor state root
        if let Err(e) = verify_l1_proof(proof, anchor_state_root) {
            bail!(
                "L1SLOAD proof verification failed for proof #{} (contract={:?}, key={:?}, block={:?}): {}",
                i,
                proof.contract_address,
                proof.storage_key,
                proof.block_number,
                e
            );
        }
        set_l1_storage_value(
            proof.contract_address,
            proof.storage_key,
            proof.block_number,
            proof.value,
        );

        info!(
            "Verified and populated L1SLOAD proof for contract={:?}, key={:?}, block={:?}, value={:?}",
            proof.contract_address, proof.storage_key, proof.block_number, proof.value
        );
    }

    info!(
        "Successfully verified and populated {} L1SLOAD storage proofs",
        l1_storage_proofs.len()
    );
    Ok(())
}

/// Populate L1SLOAD cache with storage values before EVM execution
/// This must be called before any EVM execution to ensure L1SLOAD precompile has access to L1 data
pub fn populate_l1sload_cache(l1_storage_proofs: &[L1StorageProof]) {
    for proof in l1_storage_proofs {
        set_l1_storage_value(
            proof.contract_address,
            proof.storage_key,
            proof.block_number,
            proof.value,
        );

        info!(
            "Populated L1SLOAD: contract={:?}, key={:?}, block={:?}, value={:?}",
            proof.contract_address, proof.storage_key, proof.block_number, proof.value
        );
    }
}

/// Clear L1SLOAD cache
#[inline(always)]
pub fn clear_l1sload_cache() {
    clear_l1_storage_cache();
}

/// Verify L1 storage and account proof against anchor state root using MPT proof verification
/// For non-existent accounts/storage should return zero, given that the provided proofs are empty.
fn verify_l1_proof(proof: &L1StorageProof, anchor_state_root: B256) -> Result<()> {
    // Get and verify account data
    let account_key = B256::from(keccak(proof.contract_address.as_slice()));
    let account_rlp = get_and_verify_value(account_key, anchor_state_root, &proof.account_proof)?;

    // If account doesn't exist, storage must be zero
    let actual_value = if account_rlp.is_empty() {
        // Account doesn't exist on L1, value must be zero
        B256::ZERO
    } else {
        // Account exists, check storage
        let storage_root = get_storage_root(&account_rlp).with_context(|| {
            format!(
                "Failed to extract storage root for contract {:?}",
                proof.contract_address
            )
        })?;
        let storage_key_hash = B256::from(keccak(proof.storage_key.as_slice()));
        let storage_rlp =
            get_and_verify_value(storage_key_hash, storage_root, &proof.storage_proof)
                .with_context(|| {
                    format!(
                        "Failed to verify storage proof for contract {:?}, key {:?}",
                        proof.contract_address, proof.storage_key
                    )
                })?;

        // Compare with claimed value
        if storage_rlp.is_empty() {
            B256::ZERO
        } else {
            let mut rlp_slice = storage_rlp.as_slice();
            B256::from(U256::decode(&mut rlp_slice).with_context(|| {
                format!(
                    "Failed to decode storage value for contract {:?}, key {:?}, raw bytes: 0x{}",
                    proof.contract_address,
                    proof.storage_key,
                    hex::encode(&storage_rlp)
                )
            })?)
        }
    };

    if actual_value != proof.value {
        bail!(
            "Value mismatch: expected {:?}, got {:?}",
            proof.value,
            actual_value
        );
    }

    info!(
        "L1 storage proof verified for contract {:?}, value={:?}",
        proof.contract_address, proof.value
    );
    Ok(())
}

/// Get value and verify proof
fn get_and_verify_value(key_hash: B256, root: B256, proof: &[Bytes]) -> Result<Vec<u8>> {
    // Handle empty proof array (proves non-existence at the root level)
    if proof.is_empty() {
        // For non-existent keys, verify against the root
        let nibbles = Nibbles::unpack(&key_hash);
        let proof_refs: Vec<&Bytes> = Vec::new();
        verify_proof(root, nibbles, None, proof_refs)?;
        return Ok(Vec::new());
    }

    let nibbles = Nibbles::unpack(&key_hash);
    let proof_refs: Vec<&Bytes> = proof.iter().collect();

    // Try with None first (empty/non-existent)
    if verify_proof(root, nibbles.clone(), None, proof_refs.clone()).is_ok() {
        return Ok(Vec::new());
    }

    // Extract and verify actual value
    let value = get_leaf_value(proof)?;
    let value_option = if value.is_empty() {
        None
    } else {
        Some(value.clone())
    };
    verify_proof(root, nibbles, value_option, proof_refs)?;

    Ok(value)
}

/// Extract value from leaf node
fn get_leaf_value(proof: &[Bytes]) -> Result<Vec<u8>> {
    let last_node = proof.last().ok_or_else(|| anyhow::anyhow!("Empty proof"))?;
    let mut data = last_node.as_ref();

    // Decode the list header
    let list_header = RlpHeader::decode(&mut data).with_context(|| {
        format!(
            "Failed to decode list header from proof node: 0x{}",
            hex::encode(last_node)
        )
    })?;

    if !list_header.list {
        bail!(
            "Last proof node is not a list, raw bytes: 0x{}",
            hex::encode(last_node)
        );
    }

    // For a 2-element list [path, value], we need to skip the path and decode the value
    let path_header = RlpHeader::decode(&mut data)
        .with_context(|| format!("Failed to decode path header: 0x{}", hex::encode(last_node)))?;
    data.advance(path_header.payload_length);

    // Decode the value element header to get its payload
    let value_header =
        RlpHeader::decode(&mut data).with_context(|| format!("Failed to decode value header"))?;

    // In an MPT leaf node [path, value], when the 2-element list is decoded,
    // the value field is the PAYLOAD only (not including the RLP header).
    let value = data[..value_header.payload_length].to_vec();

    info!(
        "Extracted leaf value: {} bytes (RLP-encoded) from 2-element node",
        value.len()
    );
    Ok(value)
}

/// Extract storage root from account RLP
fn get_storage_root(account_rlp: &[u8]) -> Result<B256> {
    let mut data = account_rlp;

    // Decode the list header for account [nonce, balance, storage_root, code_hash]
    let list_header = RlpHeader::decode(&mut data).with_context(|| {
        format!(
            "Failed to decode account list header: 0x{}",
            hex::encode(account_rlp)
        )
    })?;

    if !list_header.list {
        bail!(
            "Account RLP is not a list, raw bytes: 0x{}",
            hex::encode(account_rlp)
        );
    }

    // Skip nonce (field 0)
    let nonce_header = RlpHeader::decode(&mut data).with_context(|| {
        format!(
            "Failed to decode nonce header: 0x{}",
            hex::encode(account_rlp)
        )
    })?;
    data.advance(nonce_header.payload_length);

    // Skip balance (field 1)
    let balance_header = RlpHeader::decode(&mut data).with_context(|| {
        format!(
            "Failed to decode balance header: 0x{}",
            hex::encode(account_rlp)
        )
    })?;
    data.advance(balance_header.payload_length);

    // Decode storage_root (field 2)
    let storage_root_header = RlpHeader::decode(&mut data).with_context(|| {
        format!(
            "Failed to decode storage root header: 0x{}",
            hex::encode(account_rlp)
        )
    })?;

    if storage_root_header.payload_length != 32 {
        bail!(
            "Invalid storage root length: expected 32 bytes, got {}, raw bytes: 0x{}",
            storage_root_header.payload_length,
            hex::encode(account_rlp)
        );
    }

    // Extract the storage root bytes
    let storage_root_bytes = &data[..32];
    Ok(B256::from_slice(storage_root_bytes))
}
