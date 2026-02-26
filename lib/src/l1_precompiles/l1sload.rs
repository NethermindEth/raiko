use alethia_reth_evm::precompiles::l1sload::{
    clear_l1_storage, set_anchor_block_id, set_l1_storage_value, L1SLOAD_MAX_BLOCK_LOOKBACK,
};
use alloy_primitives::{Bytes, B256, U256};
use alloy_rlp::{Buf, Decodable, Header as RlpHeader};
use alloy_trie::{proof::verify_proof, Nibbles};
use anyhow::{bail, Context, Result};
use reth_primitives::Header;
use std::collections::HashMap;
use tracing::info;

use crate::input::L1StorageProof;
use crate::primitives::keccak::keccak;

/// Verify and populate L1SLOAD cache with storage values before EVM execution.
///
/// This function:
/// 1. Builds a verified map of `block_number → state_root` by walking back from the anchor block
///    through the L1 ancestor headers, verifying parent_hash linkage at each step.
/// 2. For each L1StorageProof, verifies the MPT proof against the state root of the
///    requested block number.
/// 3. Populates the L1SLOAD precompile cache with verified (address, key, block_number) → value.
///
/// # Arguments
/// * `l1_storage_proofs` - Storage proofs to verify and populate
/// * `anchor_state_root` - State root of the anchor block (trusted via anchor tx)
/// * `anchor_block_number` - Block number of the anchor block
/// * `l1_ancestor_headers` - Chain of L1 headers from oldest requested block to anchor block - 1.
///   The anchor block's state root is provided separately. These headers form a verifiable chain
///   via parent_hash linkage.
pub fn verify_and_populate_l1sload_proofs(
    l1_storage_proofs: &[L1StorageProof],
    anchor_state_root: B256,
    anchor_block_number: u64,
    l1_ancestor_headers: &[Header],
) -> Result<()> {
    if l1_storage_proofs.is_empty() {
        return Ok(());
    }

    // Set anchor block ID for the precompile's range check
    set_anchor_block_id(anchor_block_number);

    // Build verified block_number → state_root map by walking back from the anchor block.
    let state_root_map =
        build_verified_state_root_map(anchor_state_root, anchor_block_number, l1_ancestor_headers)?;

    info!(
        "Built verified state root map with {} entries (anchor block {} + {} ancestor headers)",
        state_root_map.len(),
        anchor_block_number,
        l1_ancestor_headers.len()
    );

    for (i, proof) in l1_storage_proofs.iter().enumerate() {
        let requested_block = block_number_from_b256(&proof.block_number);

        // Look up the verified state root for this block number
        let state_root = state_root_map.get(&requested_block).ok_or_else(|| {
            anyhow::anyhow!(
                "No verified state root for L1 block {} (anchor={}, available blocks: {:?})",
                requested_block,
                anchor_block_number,
                state_root_map.keys().collect::<Vec<_>>()
            )
        })?;

        // Verify L1 storage proof against this block's state root
        if let Err(e) = verify_l1_proof(proof, *state_root) {
            bail!(
                "L1SLOAD proof verification failed for proof #{} \
                 (contract={:?}, key={:?}, block={}, state_root={:?}): {}",
                i,
                proof.contract_address,
                proof.storage_key,
                requested_block,
                state_root,
                e
            );
        }

        // Populate cache with block-number-aware key (B256 block number)
        set_l1_storage_value(
            proof.contract_address,
            proof.storage_key,
            proof.block_number,
            proof.value,
        );

        info!(
            "Verified and populated L1SLOAD proof for contract={:?}, key={:?}, block={}, value={:?}",
            proof.contract_address, proof.storage_key, requested_block, proof.value
        );
    }

    info!(
        "Successfully verified and populated {} L1SLOAD storage proofs",
        l1_storage_proofs.len()
    );
    Ok(())
}

/// Populate L1SLOAD cache with storage values before EVM execution (preflight phase).
///
/// This is used during the preflight phase where proofs are not yet verified.
/// Verification happens later in the proving phase via `verify_and_populate_l1sload_proofs`.
///
/// Must be called before any EVM execution to ensure L1SLOAD precompile has access to L1 data.
pub fn populate_l1sload_cache(l1_storage_proofs: &[L1StorageProof], anchor_block_number: u64) {
    if l1_storage_proofs.is_empty() {
        return;
    }

    // Set anchor block ID for the precompile's range check
    set_anchor_block_id(anchor_block_number);
    info!("[jmadibekov] Set anchor block ID for L1SLOAD: {}", anchor_block_number);

    for proof in l1_storage_proofs {
        // Use the B256 block_number directly from the proof
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

/// Clear L1SLOAD cache and anchor block ID context
#[inline(always)]
pub fn clear_l1sload_cache() {
    clear_l1_storage();
}

/// Build a verified map of `block_number → state_root` by walking back from the anchor block.
///
/// The anchor block's state root is trusted (verified via the anchor transaction).
/// For each L1 ancestor header, we verify:
/// 1. The header's hash matches the `parent_hash` of the next (more recent) block
/// 2. The header's block number is sequential
///
/// This gives us a chain of trust from the anchor block back to the oldest requested block.
fn build_verified_state_root_map(
    anchor_state_root: B256,
    anchor_block_number: u64,
    l1_ancestor_headers: &[Header],
) -> Result<HashMap<u64, B256>> {
    let mut state_root_map = HashMap::new();

    // The anchor block's state root is trusted
    state_root_map.insert(anchor_block_number, anchor_state_root);

    if l1_ancestor_headers.is_empty() {
        return Ok(state_root_map);
    }

    // Validate lookback limit
    let oldest_header = l1_ancestor_headers.first().unwrap();
    if anchor_block_number.saturating_sub(oldest_header.number) > L1SLOAD_MAX_BLOCK_LOOKBACK {
        bail!(
            "L1 ancestor headers span too many blocks: anchor={}, oldest={}, max={}",
            anchor_block_number,
            oldest_header.number,
            L1SLOAD_MAX_BLOCK_LOOKBACK
        );
    }

    // The l1_ancestor_headers are ordered from oldest to newest (up to anchor - 1).
    // We walk from the anchor block backwards, verifying parent_hash linkage.
    //
    // Build a lookup: block_number → header for the ancestor headers
    let mut header_by_number: HashMap<u64, &Header> = HashMap::new();
    for header in l1_ancestor_headers {
        header_by_number.insert(header.number, header);
    }

    // Walk backward from anchor block - 1
    // Sort headers by block number in descending order for verification
    let mut sorted_numbers: Vec<u64> = header_by_number.keys().copied().collect();
    sorted_numbers.sort_unstable_by(|a, b| b.cmp(a)); // descending

    // Verify chain integrity: walk from newest ancestor header down to oldest
    // Each header[N]'s parent_hash must equal hash(header[N-1])
    for window in sorted_numbers.windows(2) {
        let newer_num = window[0];
        let older_num = window[1];

        let newer_header = header_by_number[&newer_num];
        let older_header = header_by_number[&older_num];

        // Verify block numbers are sequential
        if newer_num != older_num + 1 {
            bail!(
                "Non-sequential L1 ancestor headers: block {} followed by block {} (expected {})",
                older_num,
                newer_num,
                older_num + 1
            );
        }

        // Verify parent_hash linkage
        let older_hash = older_header.hash_slow();
        if newer_header.parent_hash != older_hash {
            bail!(
                "L1 ancestor header chain broken: block {} parent_hash={:?} \
                 does not match hash of block {}={:?}",
                newer_num,
                newer_header.parent_hash,
                older_num,
                older_hash
            );
        }

        // Add this header's state root to the map
        state_root_map.insert(older_num, older_header.state_root);
    }

    // Also add the newest ancestor header's state root
    if let Some(&newest_num) = sorted_numbers.first() {
        let newest_header = header_by_number[&newest_num];
        state_root_map.insert(newest_num, newest_header.state_root);

        if newest_num >= anchor_block_number {
            bail!(
                "L1 ancestor header block number {} >= anchor block number {}",
                newest_num,
                anchor_block_number
            );
        }
    }

    // Handle single-header case (windows(2) produces nothing for single element)
    if sorted_numbers.len() == 1 {
        let num = sorted_numbers[0];
        let header = header_by_number[&num];
        state_root_map.insert(num, header.state_root);
    }

    Ok(state_root_map)
}

/// Convert a B256 block number to u64
fn block_number_from_b256(block_number: &B256) -> u64 {
    let u256 = U256::from_be_bytes(block_number.0);
    u256.try_into().unwrap_or(u64::MAX)
}

/// Verify L1 storage and account proof against a given state root using MPT proof verification.
/// For non-existent accounts/storage should return zero, given that the provided proofs are empty.
fn verify_l1_proof(proof: &L1StorageProof, state_root: B256) -> Result<()> {
    // Get and verify account data
    let account_key = B256::from(keccak(proof.contract_address.as_slice()));
    let account_rlp = get_and_verify_value(account_key, state_root, &proof.account_proof)?;

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
