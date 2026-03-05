use alethia_reth_evm::precompiles::l1sload::{
    clear_l1_storage, set_anchor_block_id, set_l1_origin_block_id, set_l1_storage_value,
};
use alloy_primitives::{Bytes, B256, U256};
use alloy_rlp::{Buf, Decodable, Header as RlpHeader};
use alloy_trie::{proof::verify_proof, Nibbles};
use anyhow::{bail, Context, Result};
use reth_primitives::Header;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex, MutexGuard};
use tracing::{debug, info, trace};

use crate::input::L1StorageProof;
use crate::primitives::keccak::keccak;

/// Execution lock to serialize L1SLOAD cache operations across concurrent proving tasks.
/// The L1SLOAD precompile uses global state (L1_STORAGE_CACHE, CURRENT_ANCHOR_BLOCK_ID)
/// which is not safe for concurrent block execution. This lock must be held during the
/// entire clear → populate → EVM execute cycle.
static L1SLOAD_EXECUTION_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Acquire the L1SLOAD execution lock. Returns a MutexGuard that must be held
/// during the entire populate → EVM execute cycle to prevent concurrent cache races.
pub fn acquire_l1sload_lock() -> MutexGuard<'static, ()> {
    L1SLOAD_EXECUTION_LOCK
        .lock()
        .expect("L1SLOAD execution lock poisoned")
}

/// Verify L1SLOAD proofs via MPT against header-chain state roots, then populate the cache.
///
/// Walks backward from the L1 origin header (the root of trust, verified on-chain via
/// the Proposal event's originBlockHash) through `l1_headers` to derive trusted state roots
/// for each block in the range.
pub fn verify_and_populate_l1sload_proofs(
    l1_storage_proofs: &[L1StorageProof],
    anchor_block_number: u64,
    l1_origin_header: &Header,
    l1_headers: &[Header],
) -> Result<()> {
    if l1_storage_proofs.is_empty() {
        debug!("L1SLOAD: no proofs to verify, skipping");
        return Ok(());
    }

    let l1_origin_block_number = l1_origin_header.number;

    info!(
        "L1SLOAD: verifying {} proofs (anchor={}, l1_origin={}, headers={})",
        l1_storage_proofs.len(),
        anchor_block_number,
        l1_origin_block_number,
        l1_headers.len()
    );

    // Set block context for the precompile's range checks.
    set_anchor_block_id(anchor_block_number);
    set_l1_origin_block_id(l1_origin_block_number);

    // Build verified block_number → state_root map by walking backward from L1 origin.
    let state_root_map = build_verified_state_root_map(l1_origin_header, l1_headers)?;

    debug!(
        "L1SLOAD: built state root map with {} entries (anchor={}, l1_origin={}, headers={})",
        state_root_map.len(),
        anchor_block_number,
        l1_origin_block_number,
        l1_headers.len()
    );

    for (i, proof) in l1_storage_proofs.iter().enumerate() {
        let requested_block = block_number_from_b256(&proof.block_number)?;

        let state_root = state_root_map.get(&requested_block).ok_or_else(|| {
            anyhow::anyhow!(
                "No verified state root for L1 block {} (l1_origin={}, available blocks: {:?})",
                requested_block,
                l1_origin_block_number,
                state_root_map.keys().collect::<Vec<_>>()
            )
        })?;

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

        set_l1_storage_value(
            proof.contract_address,
            proof.storage_key,
            proof.block_number,
            proof.value,
        );
    }

    debug!(
        "L1SLOAD: verified and cached {} storage proofs",
        l1_storage_proofs.len()
    );
    Ok(())
}

/// Set L1SLOAD context (anchor/l1origin) and optionally populate cache with pre-fetched proofs.
pub fn populate_l1sload_cache(
    l1_storage_proofs: &[L1StorageProof],
    anchor_block_number: u64,
    l1_origin_block_number: u64,
) {
    set_anchor_block_id(anchor_block_number);
    set_l1_origin_block_id(l1_origin_block_number);

    if l1_storage_proofs.is_empty() {
        return;
    }

    info!(
        "L1SLOAD: populating cache (anchor={}, l1_origin={}, proofs={})",
        anchor_block_number, l1_origin_block_number, l1_storage_proofs.len()
    );

    for proof in l1_storage_proofs {
        set_l1_storage_value(
            proof.contract_address,
            proof.storage_key,
            proof.block_number,
            proof.value,
        );
    }
}

/// Clear L1SLOAD cache and block-range context
#[inline(always)]
pub fn clear_l1sload_cache() {
    clear_l1_storage();
}

/// Build a verified map of `block_number → state_root` by walking backward from the L1 origin.
///
/// The L1 origin header is the root of trust — its hash is verified on-chain against the
/// Proposal event's `originBlockHash` (set by EVM `blockhash()` in the Inbox contract).
///
/// `l1_headers` must be ordered oldest→newest, ending just below L1 origin (i.e. the last
/// header's hash must equal `l1_origin_header.parent_hash` when walking backward).
/// We walk in reverse, verifying parent_hash linkage at each step.
fn build_verified_state_root_map(
    l1_origin_header: &Header,
    l1_headers: &[Header],
) -> Result<HashMap<u64, B256>> {
    let mut state_root_map = HashMap::new();

    // The L1 origin's state root is trusted (verified via anchor linkage against on-chain proposal).
    let l1_origin_number = l1_origin_header.number;
    state_root_map.insert(l1_origin_number, l1_origin_header.state_root);

    if l1_headers.is_empty() {
        return Ok(state_root_map);
    }

    // Headers are ordered oldest→newest and do NOT include the L1 origin itself.
    // Walk in reverse (newest→oldest), starting from the origin's parent_hash since
    // the highest header in l1_headers is block (l1_origin - 1).
    let mut expected_hash = l1_origin_header.parent_hash;
    for header in l1_headers.iter().rev() {
        let header_hash = header.hash_slow();
        if header_hash != expected_hash {
            bail!(
                "L1 header chain broken at block {}: hash={:?}, expected={:?}",
                header.number,
                header_hash,
                expected_hash
            );
        }
        state_root_map.insert(header.number, header.state_root);
        expected_hash = header.parent_hash;
    }

    Ok(state_root_map)
}

/// Convert a B256 block number to u64
fn block_number_from_b256(block_number: &B256) -> Result<u64> {
    let u256 = U256::from_be_bytes(block_number.0);
    u256.try_into()
        .map_err(|_| anyhow::anyhow!("L1SLOAD block number exceeds u64: {:?}", block_number))
}

/// Verify L1 storage and account proof against a given state root using MPT proof verification.
/// For non-existent accounts/storage should return zero, given that the provided proofs are empty.
fn verify_l1_proof(proof: &L1StorageProof, state_root: B256) -> Result<()> {
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

    Ok(())
}

/// Get value and verify proof.
/// Single-pass: extracts the leaf value first, then verifies once (PR #5 optimization).
fn get_and_verify_value(key_hash: B256, root: B256, proof: &[Bytes]) -> Result<Vec<u8>> {
    let nibbles = Nibbles::unpack(&key_hash);
    let proof_refs: Vec<&Bytes> = proof.iter().collect();

    // Handle empty proof array (proves non-existence at the root level)
    if proof.is_empty() {
        verify_proof(root, nibbles, None, proof_refs)?;
        return Ok(Vec::new());
    }

    // Try to extract a leaf value from the proof. If the proof terminates at a
    // leaf node, we verify existence. If extraction fails (branch/extension node
    // termination), we verify non-existence.
    match get_leaf_value(proof) {
        Ok(value) if !value.is_empty() => {
            // Leaf with value — verify existence proof (single pass)
            verify_proof(root, nibbles, Some(value.clone()), proof_refs)?;
            Ok(value)
        }
        _ => {
            // No value extractable (non-existent key) — verify non-existence
            verify_proof(root, nibbles, None, proof_refs)?;
            Ok(Vec::new())
        }
    }
}

/// Extract value from leaf node in an MPT proof.
///
/// Distinguishes node types by RLP structure (matching alloy-trie's TrieNode::decode):
/// 1. Element count: 17 elements = branch node, 2 elements = leaf/extension
/// 2. HP (hex prefix) flag: 0x0/0x1 = extension, 0x2/0x3 = leaf
///
/// Returns Ok(value) only for leaf nodes. Returns Err for branch/extension nodes,
/// which signals non-existence to the caller.
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

    // Count elements to distinguish node types:
    // - 17 elements = branch node (non-existence proof terminates here)
    // - 2 elements = leaf or extension node
    // This matches alloy-trie's TrieNode::decode logic (nodes/mod.rs).
    let mut count_data = &data[..list_header.payload_length];
    let mut element_count = 0u32;
    while !count_data.is_empty() {
        let header = RlpHeader::decode(&mut count_data).with_context(|| {
            format!(
                "Failed to decode element {} in proof node: 0x{}",
                element_count,
                hex::encode(last_node)
            )
        })?;
        count_data.advance(header.payload_length);
        element_count += 1;
    }

    if element_count != 2 {
        bail!(
            "Last proof node has {} elements (expected 2 for leaf/extension). \
             This is a branch node, meaning the key does not exist at this path.",
            element_count
        );
    }

    // 2-element node: decode [path, value]
    let path_header = RlpHeader::decode(&mut data)
        .with_context(|| format!("Failed to decode path header: 0x{}", hex::encode(last_node)))?;

    // Check the HP (hex prefix) to distinguish leaf from extension nodes.
    // The first nibble of the compact-encoded path encodes the node type:
    //   0x0 or 0x1 → extension node
    //   0x2 or 0x3 → leaf node
    let path_bytes = &data[..path_header.payload_length];
    if !path_bytes.is_empty() {
        let hp_flag = path_bytes[0] >> 4;
        if hp_flag < 2 {
            bail!(
                "Last proof node is an extension node (HP flag=0x{:x}), not a leaf. \
                 This indicates the key does not exist at this path.",
                hp_flag
            );
        }
    }

    data.advance(path_header.payload_length);

    // Decode the value element header to get its payload
    let value_header =
        RlpHeader::decode(&mut data).with_context(|| format!("Failed to decode value header"))?;

    // In an MPT leaf node [path, value], when the 2-element list is decoded,
    // the value field is the PAYLOAD only (not including the RLP header).
    let value = data[..value_header.payload_length].to_vec();

    trace!(
        "Extracted leaf value: {} bytes (RLP-encoded) from leaf node",
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
