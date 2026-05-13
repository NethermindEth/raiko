mod l1sload;
mod l1staticcall;
pub(crate) mod witness_db;

use std::collections::HashMap;
use std::sync::MutexGuard;

use anyhow::{anyhow, Result};
use reth_primitives::Header;
use tracing::{debug, info};

use crate::anchor::get_anchor_tx_info_by_fork;
use crate::input::GuestInput;

pub use l1sload::{
    acquire_l1sload_lock, build_verified_state_root_map, clear_l1sload_cache,
    populate_l1sload_cache, verify_and_populate_l1sload_proofs,
};

pub use l1staticcall::{
    verify_and_populate_l1_staticcall_witnesses,
    verify_and_populate_l1_staticcall_witnesses_with_headers, L1STATICCALL_GAS_CAP,
};

/// Re-export L1 RPC fallback functions for L1SLOAD support
pub use alethia_reth_evm::precompiles::l1sload::{
    clear_l1_rpc_fetcher, clear_l1_rpc_served_calls, set_l1_rpc_fetcher, take_l1_rpc_served_calls,
};

/// Re-export L1STATICCALL RPC fallback functions
pub use alethia_reth_evm::precompiles::l1staticcall::{
    clear_l1_staticcall_cache, clear_l1_staticcall_rpc_fetcher,
    clear_l1_staticcall_rpc_served_calls, set_l1_staticcall_rpc_fetcher,
    take_l1_staticcall_rpc_served_calls, L1StaticCallRecord,
};

/// Reset every piece of L1 precompile global state to a known-clean baseline.
///
/// `clear_l1sload_cache` already sweeps the L1SLOAD half (cache + context + fetcher +
/// served calls — see `clear_l1_storage` in alethia-reth). The L1STATICCALL half
/// historically only cleared its cache; if a previous task panicked between
/// `set_l1_staticcall_rpc_fetcher` and `clear_l1_staticcall_rpc_fetcher`, a stale
/// fetcher could survive into the next proving task — recovered via
/// `acquire_l1sload_lock`'s poison-into-inner — and silently fire during discovery.
/// Sweeping both halves here makes the lock-recovery path resilient.
fn reset_l1_precompile_state() {
    clear_l1sload_cache();
    clear_l1_staticcall_cache();
    clear_l1_staticcall_rpc_fetcher();
    clear_l1_staticcall_rpc_served_calls();
}

/// Prepare L1 precompile state for L2 block execution: clear caches, set the shared
/// `(anchor, l1_max_anchor)` context that the L1SLOAD and L1STATICCALL precompiles read at
/// runtime, and verify+populate any L1 storage proofs and L1STATICCALL execution witnesses
/// the input carries.
///
/// Returns a [`MutexGuard`] that the caller must hold until the L2 block re-execution
/// completes — this serializes the global precompile state across concurrent proving tasks
/// and prevents cache cross-contamination.
///
/// Layout of the trust chain (verified end-to-end inside the ZK guest):
///
/// 1. The L1 max-anchor block hash is bound on-chain via the proposal commitment
///    (`originBlockHash` in Shasta / `maxAnchorBlockHash` in RealTime). Both are written by
///    the L1 EVM via `blockhash(...)` during `propose()`, so the value is cryptographically
///    verifiable.
/// 2. `input.taiko.l1_header` is the L1 header at that max-anchor block. The protocol-instance
///    layer asserts `taiko.l1_header.hash_slow() == proposal.{originBlockHash|maxAnchorBlockHash}`.
/// 3. [`build_verified_state_root_map`] walks `parent_hash` backward from
///    `taiko.l1_header` through `input.l1_headers`, producing a `block → state_root` map
///    bound to the trusted root at every step.
/// 4. L1SLOAD MPT proofs and L1STATICCALL witnesses are verified against those roots before
///    the per-call results are dropped into the precompile cache.
///
/// Same function is callable from both the raiko host (preflight verification) and the ZK
/// guest (witness-driven re-execution); the precompile state machine is identical in both
/// contexts.
pub fn prepare_l1_precompiles_for_execution(input: &GuestInput) -> Result<MutexGuard<'static, ()>> {
    let guard = acquire_l1sload_lock();

    reset_l1_precompile_state();

    if !input.chain_spec.is_taiko() {
        debug!("L1 precompiles: skipping setup for non-Taiko chain");
        return Ok(guard);
    }

    // Both L1SLOAD and L1STATICCALL precompiles need the (anchor, l1_max_anchor) context at
    // runtime even when the block has no L1SLOAD proofs — e.g. an L1STATICCALL-only batch
    // still needs the precompile's block-range check to pass during re-execution.
    let anchor_tx = input
        .taiko
        .anchor_tx
        .as_ref()
        .ok_or_else(|| anyhow!("No anchor tx for L1 precompile context"))?;
    let fork = input
        .chain_spec
        .active_fork(input.block.header.number, input.block.timestamp)
        .map_err(|e| anyhow!("Failed to determine active fork: {e}"))?;

    use alloy_consensus::Transaction;
    let (anchor_block_number, _) = get_anchor_tx_info_by_fork(fork, anchor_tx.input())
        .map_err(|e| anyhow!("Failed to decode anchor tx info: {e}"))?;
    let l1_max_anchor_block_number = input.taiko.l1_header.number;

    info!(
        "L1 precompiles: context ready (anchor={}, l1_max_anchor={}, l1sload_proofs={}, l1staticcall_witnesses={})",
        anchor_block_number,
        l1_max_anchor_block_number,
        input.l1_storage_proofs.len(),
        input.l1_staticcall_witnesses.len(),
    );
    populate_l1sload_cache(&[], anchor_block_number, l1_max_anchor_block_number);

    if !input.l1_storage_proofs.is_empty() {
        verify_and_populate_l1sload_proofs(
            &input.l1_storage_proofs,
            anchor_block_number,
            &input.taiko.l1_header,
            &input.l1_headers,
        )
        .map_err(|e| anyhow!("Failed to verify L1SLOAD proofs: {e}"))?;
    }

    if !input.l1_staticcall_witnesses.is_empty() {
        let state_root_map =
            build_verified_state_root_map(&input.taiko.l1_header, &input.l1_headers)
                .map_err(|e| anyhow!("Failed to build state root map for L1STATICCALL: {e}"))?;
        let mut header_map: HashMap<u64, &Header> = HashMap::new();
        header_map.insert(input.taiko.l1_header.number, &input.taiko.l1_header);
        for h in &input.l1_headers {
            header_map.insert(h.number, h);
        }
        verify_and_populate_l1_staticcall_witnesses_with_headers(
            &input.l1_staticcall_witnesses,
            &state_root_map,
            &header_map,
            l1_max_anchor_block_number,
        )
        .map_err(|e| anyhow!("Failed to verify L1STATICCALL witnesses: {e}"))?;
    }

    Ok(guard)
}
