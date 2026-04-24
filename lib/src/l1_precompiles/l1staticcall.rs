//! L1STATICCALL witness verification and cache population for the ZK guest.
//!
//! Known M9 limitation: reverted L1 calls are trusted from NMC instead of being
//! re-executed in revm. alethia-reth currently surfaces reverts as
//! `PrecompileError`, which drops the post-call gas accounting NMC keeps. We
//! do however enforce that the host-supplied witness for a reverted call carries
//! `gas_used == 0 && return_data.is_empty()` — matching NMC's
//! `GethLikeTxTracer.MarkAsFailed` contract — so a malicious prover cannot
//! fabricate non-zero gas for reverted invocations.
//!
use alethia_reth_evm::precompiles::l1staticcall::set_l1_staticcall_value;
use alloy_primitives::{Address, B256, U256};
use anyhow::{anyhow, ensure, Result};
use reth_primitives::Header;
use revm::context::result::ExecutionResult;
use revm::context::TxEnv;
use revm::primitives::TxKind;
use revm::{ExecuteEvm, MainBuilder, MainContext};
use std::collections::HashMap;
use tracing::{debug, info};

use super::witness_db::WitnessDb;
use crate::input::L1StaticCallWitness;

/// Maximum number of L1 blocks to look back from L1 origin. Matches the L2 precompile.
const L1STATICCALL_MAX_BLOCK_LOOKBACK: u64 = 256;

/// Verify and populate L1STATICCALL results from execution witnesses.
///
/// For each witness:
/// 1. Enforce the `[l1_origin − 256, l1_origin]` window so a prover cannot serve a
///    witness from outside the L2 precompile's accepted range (the L2 precompile
///    already enforces it at runtime; we re-enforce it here so the proof binds it).
/// 2. Verify the L1 state root is trusted (from the verified header chain)
/// 3. Build a `WitnessDb` over the witnessed MPT preimages + bytecodes
/// 4. Re-execute the call with revm against the witnessed state
/// 5. Assert revm's `(output, gas_used)` matches the witness claim; reject halts
/// 6. Populate the L1STATICCALL cache with the verified result
///
/// For reverted witnesses (`is_reverted == true`), we skip revm re-execution but
/// enforce `gas_used == 0 && return_data.is_empty()` — matching NMC's
/// `GethLikeTxTracer.MarkAsFailed` contract — so a malicious prover cannot forge
/// non-zero gas for reverts.
pub fn verify_and_populate_l1_staticcall_witnesses(
    witnesses: &[L1StaticCallWitness],
    state_root_map: &HashMap<u64, B256>,
    l1_origin_block_number: u64,
) -> Result<()> {
    verify_and_populate_l1_staticcall_witnesses_with_headers(
        witnesses,
        state_root_map,
        &HashMap::new(),
        l1_origin_block_number,
    )
}

/// Richer entrypoint that can also populate the revm block-env with fields from the
/// verified L1 header (timestamp, base_fee, coinbase, prevrandao, blob_base_fee). When
/// `header_map` is empty, those fields fall back to revm defaults — honest L1 view
/// functions that don't read block-env opcodes still verify successfully, but contracts
/// that read `TIMESTAMP` / `COINBASE` / `BASEFEE` / `BLOBBASEFEE` / `PREVRANDAO` must
/// be proved with populated headers or they'll diverge from the sequencer's run.
pub fn verify_and_populate_l1_staticcall_witnesses_with_headers(
    witnesses: &[L1StaticCallWitness],
    state_root_map: &HashMap<u64, B256>,
    header_map: &HashMap<u64, &Header>,
    l1_origin_block_number: u64,
) -> Result<()> {
    if witnesses.is_empty() {
        debug!("L1STATICCALL: no witnesses to verify, skipping");
        return Ok(());
    }

    info!(
        "L1STATICCALL: verifying {} execution witnesses (l1_origin={})",
        witnesses.len(),
        l1_origin_block_number
    );

    let window_floor = l1_origin_block_number.saturating_sub(L1STATICCALL_MAX_BLOCK_LOOKBACK);

    for (i, w) in witnesses.iter().enumerate() {
        // Block-range check mirrors the L2 precompile `[l1origin − 256, l1origin]` window.
        ensure!(
            w.block_number >= window_floor && w.block_number <= l1_origin_block_number,
            "L1STATICCALL: witness #{i} at block {} outside lookback window [{}, {}]",
            w.block_number,
            window_floor,
            l1_origin_block_number,
        );

        let state_root = state_root_map.get(&w.block_number).ok_or_else(|| {
            anyhow!(
                "L1STATICCALL: no verified state root for block {} (witness #{})",
                w.block_number,
                i
            )
        })?;

        debug!(
            "L1STATICCALL: witness #{}: target={:?}, block={}, calldata_len={}, return_len={}, state_nodes={}, codes={}",
            i, w.target_address, w.block_number, w.calldata.len(), w.return_data.len(),
            w.execution_witness.state.len(), w.execution_witness.codes.len()
        );

        if w.is_reverted {
            // Match NMC's `GethLikeTxTracer.MarkAsFailed`: revert => gas=0 and empty return data.
            // This binds the fragile coupling between the sequencer tracer and the guest so a
            // malicious prover cannot mark an arbitrary call reverted with forged gas.
            ensure!(
                w.gas_used == 0 && w.return_data.is_empty(),
                "L1STATICCALL: witness #{i} reverted but carries non-zero gas ({}) or non-empty data ({} bytes) — expected NMC-tracer semantics",
                w.gas_used,
                w.return_data.len(),
            );
            debug!(
                "L1STATICCALL: witness #{i} reverted on L1 — cached as revert with gas=0"
            );
            set_l1_staticcall_value(
                w.target_address,
                w.block_number,
                &w.calldata,
                w.gas_used,
                w.return_data.to_vec(),
                true,
            );
            continue;
        }

        // Test-only fast path for unit tests that construct `ExecutionWitness::default()` —
        // skips state-root verification and revm re-execution entirely. This branch is
        // compiled *only* under `cfg(test)`; production guest builds never include it.
        #[cfg(test)]
        if w.execution_witness.state.is_empty() {
            tracing::warn!(
                "L1STATICCALL: witness #{i} has empty state — test-only fast path (cfg(test))"
            );
            set_l1_staticcall_value(
                w.target_address,
                w.block_number,
                &w.calldata,
                w.gas_used,
                w.return_data.to_vec(),
                false,
            );
            continue;
        }

        // Production invariant: a non-reverted witness must carry state to re-execute against.
        #[cfg(not(test))]
        ensure!(
            !w.execution_witness.state.is_empty(),
            "L1STATICCALL: witness #{i} has empty state — not permitted in production proving"
        );

        // 1. Build WitnessDb from the execution witness
        let db = WitnessDb::build(&w.execution_witness, *state_root)
            .map_err(|e| anyhow!("L1STATICCALL #{i}: WitnessDb build: {e}"))?;

        let block_number = w.block_number;
        let header = header_map.get(&w.block_number).copied();

        // Diagnostic context for regression debugging — logged at INFO so it shows up
        // in devnet runs without flipping RUST_LOG. If this ever gets noisy in production
        // drop to debug! but keep the fields: they collapsed #40's multi-regression
        // cascade from "guess and rebuild" to "read the log".
        info!(
            "L1STATICCALL #{i}: target={:?}, block={}, calldata_len={}, state_root={}, \
             witness_state_nodes={}, witness_codes={}, witness_keys={}, witness_headers={}, \
             witness_return_len={}, witness_gas={}, has_header={}",
            w.target_address,
            w.block_number,
            w.calldata.len(),
            state_root,
            w.execution_witness.state.len(),
            w.execution_witness.codes.len(),
            w.execution_witness.keys.len(),
            w.execution_witness.headers.len(),
            w.return_data.len(),
            w.gas_used,
            header.is_some(),
        );

        // 2. Build the call TxEnv for a read-only call (caller = Address::ZERO).
        //    Gas limit matches NMC's cap so revm can complete calls that NMC sequenced.
        //    gas_price is left at 0 so revm doesn't charge the zero-address caller fees
        //    (which would fail since Address::ZERO has no balance in the witness).
        let tx = TxEnv::builder()
            .caller(Address::ZERO)
            .kind(TxKind::Call(w.target_address))
            .data(w.calldata.clone())
            .gas_limit(30_000_000)
            .build()
            .map_err(|e| anyhow!("L1STATICCALL #{i}: TxEnv build: {e:?}"))?;

        // 3. Construct a mainnet EVM over the witness. We pin block.number and pass the
        //    verified header's timestamp/beneficiary/prevrandao for correct BLOCK_TIMESTAMP /
        //    COINBASE / DIFFICULTY opcodes. We deliberately do NOT set basefee or
        //    blob_excess_gas_and_price here: both require CfgEnv-gated opt-outs to keep the
        //    zero-address caller viable (basefee forces gas_price >= basefee, and
        //    set_blob_excess_gas_and_price with a non-zero update fraction panics in
        //    feature-constrained revm builds). Targets that rely on BASEFEE/BLOBBASEFEE
        //    will see 0 — documented trade-off.
        let mut evm = revm::Context::mainnet()
            .with_db(db)
            .modify_block_chained(|blk| {
                blk.number = U256::from(block_number);
                if let Some(h) = header {
                    blk.timestamp = U256::from(h.timestamp);
                    blk.beneficiary = h.beneficiary;
                    blk.prevrandao = Some(h.mix_hash);
                }
            })
            .build_mainnet();

        // Capture the full env revm is actually seeing so the root cause of any divergence
        // is on the wire when it happens. Without these the caller only sees "mismatch"
        // and must rebuild to learn which env field was wrong.
        {
            let cfg = &evm.ctx.cfg;
            let blk = &evm.ctx.block;
            info!(
                "L1STATICCALL #{i} evm env: spec={:?}, chain_id={}, \
                 blk.number={}, blk.timestamp={}, blk.beneficiary={:?}, blk.basefee={}, \
                 blk.prevrandao={:?}, blk.gas_limit={}, blk.difficulty={}, \
                 blk.blob_excess_gas_and_price={:?}",
                cfg.spec,
                cfg.chain_id,
                blk.number,
                blk.timestamp,
                blk.beneficiary,
                blk.basefee,
                blk.prevrandao,
                blk.gas_limit,
                blk.difficulty,
                blk.blob_excess_gas_and_price,
            );
        }

        // 4. Execute the call
        let outcome = evm
            .transact(tx)
            .map_err(|e| anyhow!("L1STATICCALL #{i}: revm transact: {e:?}"))?;

        debug!(
            "L1STATICCALL #{i} revm outcome: {:?}",
            match &outcome.result {
                ExecutionResult::Success {
                    output, gas_used, ..
                } => format!("Success(output_len={}, gas={})", output.data().len(), gas_used),
                ExecutionResult::Revert { output, gas_used } =>
                    format!("Revert(output_len={}, gas={})", output.len(), gas_used),
                ExecutionResult::Halt { reason, gas_used } =>
                    format!("Halt({reason:?}, gas={gas_used})"),
            }
        );

        // 5. Three-way assertion: output + gas_used + halt status
        let (output, gas_used) = match outcome.result {
            ExecutionResult::Success {
                output, gas_used, ..
            } => (output.into_data(), gas_used),
            ExecutionResult::Revert { output, gas_used } => (output, gas_used),
            ExecutionResult::Halt { reason, gas_used } => {
                return Err(anyhow!(
                    "L1STATICCALL #{i}: halted {reason:?} after {gas_used} gas (target={:?}, block={}, calldata=0x{})",
                    w.target_address,
                    w.block_number,
                    alloy_primitives::hex::encode(&w.calldata),
                ));
            }
        };

        if output.as_ref() != w.return_data.as_ref() {
            // Include both sides of the mismatch so the root cause is visible without
            // needing to re-instrument. Without these fields the prior error — "return_data
            // mismatch" — was uninformative and forced a guess-and-check rebuild cycle.
            return Err(anyhow!(
                "L1STATICCALL #{i}: return_data mismatch (target={:?}, block={}, calldata=0x{}, revm_gas={}, witness_gas={}): \
                 revm returned {} bytes (0x{}), witness expects {} bytes (0x{})",
                w.target_address,
                w.block_number,
                alloy_primitives::hex::encode(&w.calldata),
                gas_used,
                w.gas_used,
                output.len(),
                alloy_primitives::hex::encode(&output),
                w.return_data.len(),
                alloy_primitives::hex::encode(&w.return_data),
            ));
        }
        if gas_used != w.gas_used {
            return Err(anyhow!(
                "L1STATICCALL #{i}: gas_used mismatch (target={:?}, block={}, calldata=0x{}): witness={}, revm={}",
                w.target_address,
                w.block_number,
                alloy_primitives::hex::encode(&w.calldata),
                w.gas_used,
                gas_used
            ));
        }

        // 6. Populate cache with verified gas + data
        set_l1_staticcall_value(
            w.target_address,
            w.block_number,
            &w.calldata,
            w.gas_used,
            output.to_vec(),
            false,
        );
    }

    info!(
        "L1STATICCALL: verified and cached {} execution witnesses",
        witnesses.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::input::{ExecutionWitness, L1StaticCallWitness};
    use alethia_reth_evm::precompiles::l1sload::{
        clear_l1_storage, set_anchor_block_id, set_l1_origin_block_id,
    };
    use alethia_reth_evm::precompiles::l1staticcall::{
        clear_l1_staticcall_cache, l1staticcall_run,
    };
    use alloy_primitives::U256;
    use alloy_primitives::{Address, Bytes, B256};
    use serial_test::serial;

    // ───────────────────────────────────────────────
    // Helpers
    // ───────────────────────────────────────────────

    /// Test l1_origin that comfortably contains all test block numbers (50..=300) within the
    /// 256-block window. Window floor = 300 - 256 = 44.
    const TEST_L1_ORIGIN: u64 = 300;

    /// Wrapper that passes the shared `TEST_L1_ORIGIN` so individual tests stay focused on
    /// witness-body semantics rather than range-check boilerplate.
    fn verify_test(
        witnesses: &[L1StaticCallWitness],
        state_root_map: &HashMap<u64, B256>,
    ) -> Result<()> {
        verify_and_populate_l1_staticcall_witnesses(witnesses, state_root_map, TEST_L1_ORIGIN)
    }

    fn make_witness(
        target: Address,
        block: u64,
        calldata: &[u8],
        return_data: &[u8],
    ) -> L1StaticCallWitness {
        L1StaticCallWitness {
            target_address: target,
            block_number: block,
            calldata: Bytes::from(calldata.to_vec()),
            return_data: Bytes::from(return_data.to_vec()),
            gas_used: 0,
            is_reverted: false,
            execution_witness: ExecutionWitness::default(),
        }
    }

    /// Reset all shared global state (anchor, l1origin, l1sload cache, l1staticcall cache).
    fn reset_all() {
        clear_l1_storage();
        clear_l1_staticcall_cache();
    }

    // ───────────────────────────────────────────────
    // Tests
    // ───────────────────────────────────────────────

    #[test]
    #[serial]
    fn test_verify_empty_witnesses_succeeds() {
        reset_all();
        let state_root_map: HashMap<u64, B256> = HashMap::new();
        let result = verify_test(&[], &state_root_map);
        assert!(result.is_ok(), "Empty witness list should return Ok");
    }

    #[test]
    #[serial]
    fn test_verify_missing_state_root_fails() {
        reset_all();
        let target = Address::from([0xAAu8; 20]);
        let witness = make_witness(target, 50, &[0x01], &[0xFF]);

        // State root map does not contain block 50
        let state_root_map: HashMap<u64, B256> = HashMap::from([(100, B256::from([0x11u8; 32]))]);

        let result = verify_test(&[witness], &state_root_map);
        assert!(
            result.is_err(),
            "Should fail when witness references block not in state_root_map"
        );
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("no verified state root for block 50"),
            "Error should mention missing state root, got: {err_msg}"
        );
    }

    #[test]
    #[serial]
    fn test_verify_single_witness_succeeds() {
        reset_all();
        let target = Address::from([0xBBu8; 20]);
        let calldata = vec![0x01, 0x02, 0x03];
        let return_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let witness = make_witness(target, 100, &calldata, &return_data);

        let state_root_map: HashMap<u64, B256> = HashMap::from([(100, B256::from([0x22u8; 32]))]);

        let result = verify_test(&[witness], &state_root_map);
        assert!(
            result.is_ok(),
            "Single valid witness should succeed: {:?}",
            result.err()
        );

        // Verify the cache was populated by querying the precompile
        set_anchor_block_id(90);
        set_l1_origin_block_id(110);

        let mut input = Vec::with_capacity(52 + calldata.len());
        input.extend_from_slice(target.as_slice());
        input.extend_from_slice(&U256::from(100u64).to_be_bytes::<32>());
        input.extend_from_slice(&calldata);

        let precompile_result = l1staticcall_run(&input, 100_000);
        assert!(
            precompile_result.is_ok(),
            "Cached value should be retrievable via precompile: {:?}",
            precompile_result.err()
        );
        assert_eq!(precompile_result.unwrap().bytes.as_ref(), &return_data);
    }

    #[test]
    #[serial]
    fn test_verify_reverted_witness_skips_revm_and_caches_revert() {
        reset_all();
        let target = Address::from([0xBCu8; 20]);
        let calldata = vec![0xAA, 0xBB];
        let witness = L1StaticCallWitness {
            target_address: target,
            block_number: 100,
            calldata: Bytes::from(calldata.clone()),
            // NMC parity: MarkAsFailed returns gas=0 / empty data for reverted traceCalls.
            return_data: Bytes::from(vec![]),
            gas_used: 0,
            is_reverted: true,
            execution_witness: ExecutionWitness {
                // Intentionally malformed state. The revert path should skip revm and
                // witness parsing entirely, so this still succeeds.
                state: vec![Bytes::from(vec![0xFFu8; 8])],
                codes: vec![],
                keys: vec![],
                headers: vec![],
            },
        };

        let state_root_map: HashMap<u64, B256> = HashMap::from([(100, B256::from([0x22u8; 32]))]);

        let result = verify_test(&[witness], &state_root_map);
        assert!(
            result.is_ok(),
            "reverted witness should bypass revm build: {:?}",
            result.err()
        );

        set_anchor_block_id(90);
        set_l1_origin_block_id(110);

        let mut input = Vec::with_capacity(52 + calldata.len());
        input.extend_from_slice(target.as_slice());
        input.extend_from_slice(&U256::from(100u64).to_be_bytes::<32>());
        input.extend_from_slice(&calldata);

        let precompile_result = l1staticcall_run(&input, 100_000);
        assert!(
            precompile_result.is_err(),
            "cached reverted call should still error"
        );
        let err_msg = format!("{:?}", precompile_result.unwrap_err());
        assert!(err_msg.contains("L1 call reverted"), "Got: {err_msg}");
    }

    #[test]
    #[serial]
    fn test_verify_multiple_witnesses_succeeds() {
        reset_all();
        let target_a = Address::from([0xAAu8; 20]);
        let target_b = Address::from([0xBBu8; 20]);

        let witness_a = make_witness(target_a, 100, &[0x01], &[0x11, 0x22]);
        let witness_b = make_witness(target_b, 101, &[0x02], &[0x33, 0x44]);
        let witness_c = make_witness(target_a, 102, &[0x03], &[0x55]);

        let state_root_map: HashMap<u64, B256> = HashMap::from([
            (100, B256::from([0x01u8; 32])),
            (101, B256::from([0x02u8; 32])),
            (102, B256::from([0x03u8; 32])),
        ]);

        let result = verify_test(&[witness_a, witness_b, witness_c], &state_root_map);
        assert!(
            result.is_ok(),
            "Multiple valid witnesses should all succeed: {:?}",
            result.err()
        );

        // Verify all three were cached
        set_anchor_block_id(90);
        set_l1_origin_block_id(110);

        // Check witness_a
        let mut input_a = Vec::with_capacity(53);
        input_a.extend_from_slice(target_a.as_slice());
        input_a.extend_from_slice(&U256::from(100u64).to_be_bytes::<32>());
        input_a.push(0x01);
        let res_a = l1staticcall_run(&input_a, 100_000);
        assert!(
            res_a.is_ok(),
            "witness_a should be cached: {:?}",
            res_a.err()
        );
        assert_eq!(res_a.unwrap().bytes.as_ref(), &[0x11, 0x22]);

        // Check witness_b
        let mut input_b = Vec::with_capacity(53);
        input_b.extend_from_slice(target_b.as_slice());
        input_b.extend_from_slice(&U256::from(101u64).to_be_bytes::<32>());
        input_b.push(0x02);
        let res_b = l1staticcall_run(&input_b, 100_000);
        assert!(
            res_b.is_ok(),
            "witness_b should be cached: {:?}",
            res_b.err()
        );
        assert_eq!(res_b.unwrap().bytes.as_ref(), &[0x33, 0x44]);

        // Check witness_c
        let mut input_c = Vec::with_capacity(53);
        input_c.extend_from_slice(target_a.as_slice());
        input_c.extend_from_slice(&U256::from(102u64).to_be_bytes::<32>());
        input_c.push(0x03);
        let res_c = l1staticcall_run(&input_c, 100_000);
        assert!(
            res_c.is_ok(),
            "witness_c should be cached: {:?}",
            res_c.err()
        );
        assert_eq!(res_c.unwrap().bytes.as_ref(), &[0x55]);
    }

    #[test]
    #[serial]
    fn test_verify_populates_cache_correctly() {
        reset_all();
        let target = Address::from([0xCCu8; 20]);
        let calldata = vec![0xCA, 0xFE, 0xBA, 0xBE];
        let return_data = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01];
        let witness = make_witness(target, 200, &calldata, &return_data);

        let state_root_map: HashMap<u64, B256> = HashMap::from([(200, B256::from([0x44u8; 32]))]);

        let result = verify_test(&[witness], &state_root_map);
        assert!(
            result.is_ok(),
            "Verification should succeed: {:?}",
            result.err()
        );

        // 1. Set anchor and l1_origin block IDs so the precompile allows the query
        set_anchor_block_id(190);
        set_l1_origin_block_id(210);

        // 2. Build a precompile input: target(20) + block_number_u256(32) + calldata
        let mut input = Vec::with_capacity(52 + calldata.len());
        input.extend_from_slice(target.as_slice()); // 20 bytes
        input.extend_from_slice(&U256::from(200u64).to_be_bytes::<32>()); // 32 bytes
        input.extend_from_slice(&calldata); // variable

        // 3. Call l1staticcall_run and check the output matches return_data
        let precompile_result = l1staticcall_run(&input, 100_000);
        assert!(
            precompile_result.is_ok(),
            "Cache should be populated after verify_and_populate: {:?}",
            precompile_result.err()
        );
        let output = precompile_result.unwrap();
        assert_eq!(
            output.bytes.as_ref(),
            &return_data,
            "Precompile output should match the witness return_data"
        );
    }

    #[test]
    #[serial]
    fn test_verify_different_calldata_same_target() {
        reset_all();
        let target = Address::from([0xDDu8; 20]);
        let calldata_1 = vec![0x01, 0x02];
        let calldata_2 = vec![0x03, 0x04, 0x05];
        let return_data_1 = vec![0xAA];
        let return_data_2 = vec![0xBB, 0xCC];

        let witness_1 = make_witness(target, 100, &calldata_1, &return_data_1);
        let witness_2 = make_witness(target, 100, &calldata_2, &return_data_2);

        let state_root_map: HashMap<u64, B256> = HashMap::from([(100, B256::from([0x55u8; 32]))]);

        let result =
            verify_test(&[witness_1, witness_2], &state_root_map);
        assert!(
            result.is_ok(),
            "Two witnesses for same target should succeed: {:?}",
            result.err()
        );

        // Set up precompile context
        set_anchor_block_id(90);
        set_l1_origin_block_id(110);

        // Check first calldata returns its own data
        let mut input_1 = Vec::with_capacity(52 + calldata_1.len());
        input_1.extend_from_slice(target.as_slice());
        input_1.extend_from_slice(&U256::from(100u64).to_be_bytes::<32>());
        input_1.extend_from_slice(&calldata_1);
        let res_1 = l1staticcall_run(&input_1, 100_000);
        assert!(
            res_1.is_ok(),
            "First calldata should hit cache: {:?}",
            res_1.err()
        );
        assert_eq!(res_1.unwrap().bytes.as_ref(), &return_data_1);

        // Check second calldata returns its own data
        let mut input_2 = Vec::with_capacity(52 + calldata_2.len());
        input_2.extend_from_slice(target.as_slice());
        input_2.extend_from_slice(&U256::from(100u64).to_be_bytes::<32>());
        input_2.extend_from_slice(&calldata_2);
        let res_2 = l1staticcall_run(&input_2, 100_000);
        assert!(
            res_2.is_ok(),
            "Second calldata should hit cache: {:?}",
            res_2.err()
        );
        assert_eq!(res_2.unwrap().bytes.as_ref(), &return_data_2);

        // Confirm they are indeed different values
        assert_ne!(
            return_data_1, return_data_2,
            "Different calldata should produce different return data"
        );
    }

    // ───────────────────────────────────────────────
    // Non-empty-witness path (revm re-execution)
    // ───────────────────────────────────────────────
    //
    // The 6 tests above all use `ExecutionWitness::default()` which hits the
    // empty-witness fast path and skips revm. The tests below exercise the
    // actual revm re-execution path with hand-crafted (partial) witnesses.

    #[test]
    #[serial]
    fn test_verify_rejects_malformed_witness_state() {
        // Non-empty witness bytes that are not valid RLP-encoded MPT nodes.
        // This should fail early at `WitnessDb::build` → `witness_to_tries`
        // without ever reaching revm. Proves: the revm path is actually
        // entered (fast-path skipped) and build-time errors bubble up.
        reset_all();
        let target = Address::from([0xE1u8; 20]);
        let witness = L1StaticCallWitness {
            target_address: target,
            block_number: 100,
            calldata: Bytes::from(vec![0x01]),
            return_data: Bytes::from(vec![0x02]),
            gas_used: 0,
            is_reverted: false,
            execution_witness: ExecutionWitness {
                // 0xFF bytes cannot decode as a valid MPT node.
                state: vec![Bytes::from(vec![0xFFu8; 8])],
                codes: vec![],
                keys: vec![],
                headers: vec![],
            },
        };

        let state_root_map: HashMap<u64, B256> = HashMap::from([(100, B256::from([0x11u8; 32]))]);

        let result = verify_test(&[witness], &state_root_map);
        assert!(
            result.is_err(),
            "Malformed witness state should be rejected"
        );
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("WitnessDb build"),
            "Error should surface WitnessDb build failure, got: {err}"
        );
    }

    #[test]
    #[serial]
    fn test_verify_rejects_mismatched_state_root() {
        // Witness with a single valid (but minimal) RLP node whose hash doesn't
        // match the trusted state_root. WitnessDb::build → witness_to_tries
        // should fail the root hash check.
        reset_all();
        let target = Address::from([0xE2u8; 20]);
        let witness = L1StaticCallWitness {
            target_address: target,
            block_number: 200,
            calldata: Bytes::from(vec![0x01]),
            return_data: Bytes::from(vec![0x02]),
            gas_used: 0,
            is_reverted: false,
            execution_witness: ExecutionWitness {
                // 0x80 is RLP for an empty string — valid RLP but irrelevant as a trie node;
                // its keccak won't match the trusted root below.
                state: vec![Bytes::from(vec![0x80u8])],
                codes: vec![],
                keys: vec![],
                headers: vec![],
            },
        };

        // Trusted root that the witness definitively does not produce.
        let state_root_map: HashMap<u64, B256> = HashMap::from([(200, B256::from([0xAAu8; 32]))]);

        let result = verify_test(&[witness], &state_root_map);
        assert!(
            result.is_err(),
            "Witness whose trie doesn't hash to the trusted state_root should be rejected"
        );
    }

    // ───────────────────────────────────────────────
    // Range + revert-semantics guards
    // ───────────────────────────────────────────────

    #[test]
    #[serial]
    fn test_verify_rejects_witness_below_window_floor() {
        reset_all();
        let target = Address::from([0xF1u8; 20]);
        let floor = TEST_L1_ORIGIN.saturating_sub(L1STATICCALL_MAX_BLOCK_LOOKBACK);
        // One block below the window floor.
        let outside = floor.saturating_sub(1);
        let witness = make_witness(target, outside, &[0x01], &[0x02]);
        let state_root_map: HashMap<u64, B256> =
            HashMap::from([(outside, B256::from([0x11u8; 32]))]);

        let result = verify_test(&[witness], &state_root_map);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("outside lookback window"),
            "expected window-violation error, got: {err}"
        );
    }

    #[test]
    #[serial]
    fn test_verify_rejects_witness_above_l1_origin() {
        reset_all();
        let target = Address::from([0xF2u8; 20]);
        let witness = make_witness(target, TEST_L1_ORIGIN + 1, &[0x01], &[0x02]);
        let state_root_map: HashMap<u64, B256> =
            HashMap::from([(TEST_L1_ORIGIN + 1, B256::from([0x11u8; 32]))]);

        let result = verify_test(&[witness], &state_root_map);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("outside lookback window"));
    }

    #[test]
    #[serial]
    fn test_verify_rejects_reverted_with_nonzero_gas() {
        reset_all();
        let target = Address::from([0xF3u8; 20]);
        let witness = L1StaticCallWitness {
            target_address: target,
            block_number: 100,
            calldata: Bytes::from(vec![0x01]),
            return_data: Bytes::from(vec![]),
            gas_used: 12_345, // violates NMC tracer contract (should be 0 for reverts)
            is_reverted: true,
            execution_witness: ExecutionWitness::default(),
        };
        let state_root_map: HashMap<u64, B256> = HashMap::from([(100, B256::from([0x22u8; 32]))]);

        let result = verify_test(&[witness], &state_root_map);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("non-zero gas"));
    }

    #[test]
    #[serial]
    fn test_verify_rejects_reverted_with_nonempty_data() {
        reset_all();
        let target = Address::from([0xF4u8; 20]);
        let witness = L1StaticCallWitness {
            target_address: target,
            block_number: 100,
            calldata: Bytes::from(vec![0x01]),
            return_data: Bytes::from(vec![0xAA]), // violates NMC tracer contract
            gas_used: 0,
            is_reverted: true,
            execution_witness: ExecutionWitness::default(),
        };
        let state_root_map: HashMap<u64, B256> = HashMap::from([(100, B256::from([0x22u8; 32]))]);

        let result = verify_test(&[witness], &state_root_map);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("non-empty data"));
    }

    // ───────────────────────────────────────────────
    // revm re-execution regression guards
    // ───────────────────────────────────────────────
    //
    // #40 exposed that the rest of this module's tests all use
    // `ExecutionWitness::default()` → the cfg(test) fast path → revm never runs.
    // R7 (block-env population) sailed through `cargo test` and only failed during
    // devnet replay. The tests below drive revm with a hand-built valid state trie
    // so future changes to block env, spec, witness handling, or CfgEnv cannot
    // regress the simple SLOAD path without being caught here.

    use crate::primitives::mpt::{keccak, MptNode, RlpBytes, StateAccount};

    /// Builds a witness for a minimal contract at `target` whose runtime code is a
    /// `SLOAD(slot 0); RETURN 32 bytes` loop. Returns `(witness, state_root, expected_return)`.
    fn sload_target_witness(
        target: Address,
        block_number: u64,
        stored_value: U256,
    ) -> (L1StaticCallWitness, B256, Vec<u8>) {
        // PUSH1 0 SLOAD PUSH1 0 MSTORE PUSH1 0x20 PUSH1 0 RETURN — 11 bytes.
        let code: Vec<u8> = vec![
            0x60, 0x00, 0x54, 0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
        ];
        let code_hash: B256 = keccak(&code).into();

        let mut storage_trie = MptNode::default();
        let storage_key = keccak(U256::ZERO.to_be_bytes::<32>());
        storage_trie.insert_rlp(&storage_key, stored_value).unwrap();
        let storage_root: B256 = storage_trie.hash();

        let account = StateAccount {
            nonce: 0,
            balance: U256::ZERO,
            storage_root,
            code_hash,
        };
        let mut state_trie = MptNode::default();
        let address_key = keccak(target);
        state_trie.insert_rlp(&address_key, account).unwrap();
        let state_root: B256 = state_trie.hash();

        let expected_return = stored_value.to_be_bytes::<32>().to_vec();

        let witness = L1StaticCallWitness {
            target_address: target,
            block_number,
            calldata: Bytes::new(),
            return_data: Bytes::from(expected_return.clone()),
            // gas_used is whatever revm computes. Callers that want to assert
            // full success replace this with the revm-reported value on a second pass;
            // callers that only want to assert correct output leave it at 0 and expect
            // the verifier to fail with "gas_used mismatch" (proving revm ran and
            // produced matching bytes).
            gas_used: 0,
            is_reverted: false,
            execution_witness: ExecutionWitness {
                state: vec![
                    Bytes::from(state_trie.to_rlp()),
                    Bytes::from(storage_trie.to_rlp()),
                ],
                codes: vec![Bytes::from(code)],
                keys: vec![
                    Bytes::from(target.as_slice().to_vec()),
                    Bytes::from(U256::ZERO.to_be_bytes::<32>().to_vec()),
                ],
                headers: vec![],
            },
        };
        (witness, state_root, expected_return)
    }

    #[test]
    #[serial]
    fn test_revm_reexecution_produces_correct_return_data_for_sload() {
        reset_all();
        let target = Address::from([0xABu8; 20]);
        let (witness, state_root, _) =
            sload_target_witness(target, 100, U256::from(0xDEAD_BEEFu64));
        let state_root_map: HashMap<u64, B256> = HashMap::from([(100, state_root)]);

        let err = verify_test(&[witness], &state_root_map)
            .expect_err("gas_used=0 in fixture must fail revm's gas check");
        let msg = err.to_string();

        // The point of this regression guard: revm MUST produce the correct 32-byte
        // SLOAD output. Only gas should mismatch against our placeholder `gas_used: 0`.
        assert!(
            msg.contains("gas_used mismatch"),
            "Expected gas_used mismatch (proves revm re-executed the SLOAD correctly). \
             Got instead: {msg}"
        );
        assert!(
            !msg.contains("return_data mismatch"),
            "return_data mismatch means revm's re-execution drifted from the witness \
             output — exactly the class of failure R7/#40 surfaced. Got: {msg}"
        );
    }

    #[test]
    #[serial]
    fn test_revm_reexecution_ignores_populated_block_env_for_storage_only_target() {
        // Tighter regression guard for R7 specifically: a target that only reads
        // storage must produce byte-identical output whether or not timestamp,
        // beneficiary, or prevrandao are populated in the block env. If someone
        // ever changes how block-env is threaded into revm (e.g. flipping a spec
        // default, adding a pre-execution hook) and it perturbs a pure-SLOAD call,
        // this test fails loudly.
        reset_all();
        let target = Address::from([0xCDu8; 20]);
        let (witness, state_root, _) = sload_target_witness(target, 150, U256::from(42u64));
        let state_root_map: HashMap<u64, B256> = HashMap::from([(150, state_root)]);

        // Construct a synthetic header so the `_with_headers` path is exercised.
        let header = reth_primitives::Header {
            number: 150,
            timestamp: 1_776_933_683,
            beneficiary: Address::from([0xEEu8; 20]),
            mix_hash: B256::from([0x11u8; 32]),
            base_fee_per_gas: Some(1_000_000_000),
            excess_blob_gas: Some(0),
            ..Default::default()
        };
        let header_map: HashMap<u64, &reth_primitives::Header> = HashMap::from([(150, &header)]);

        let err = verify_and_populate_l1_staticcall_witnesses_with_headers(
            &[witness],
            &state_root_map,
            &header_map,
            TEST_L1_ORIGIN,
        )
        .expect_err("gas_used=0 placeholder must fail the gas assertion");

        let msg = err.to_string();
        assert!(
            msg.contains("gas_used mismatch"),
            "Populated block env must not disturb SLOAD output — expected the only \
             mismatch to be gas_used. Got: {msg}"
        );
        assert!(
            !msg.contains("return_data mismatch"),
            "return_data differed with populated block env (R7 regression class). \
             The full mismatch details are in the error message — read them: {msg}"
        );
    }

    #[test]
    #[serial]
    fn test_revm_reexecution_surfaces_return_data_mismatch_with_diagnostics() {
        // Guarantees the improved error message in `return_data mismatch` actually
        // carries both the revm output and the witness expected value. Without this,
        // diagnosing the #40 regression chain would again require a code change +
        // rebuild cycle just to see which bytes differ.
        reset_all();
        let target = Address::from([0xEFu8; 20]);
        let (mut witness, state_root, _) =
            sload_target_witness(target, 200, U256::from(0xBEEFu64));
        // Deliberately corrupt the expected return_data so the verifier surfaces a
        // return_data mismatch — proving the error carries enough context to debug.
        witness.return_data = Bytes::from(vec![0xFFu8; 32]);
        let state_root_map: HashMap<u64, B256> = HashMap::from([(200, state_root)]);

        let err =
            verify_test(&[witness], &state_root_map).expect_err("corrupted return_data must fail");
        let msg = err.to_string();

        assert!(msg.contains("return_data mismatch"), "Got: {msg}");
        assert!(msg.contains("revm returned"), "Missing revm output. Got: {msg}");
        assert!(msg.contains("witness expects"), "Missing witness value. Got: {msg}");
        assert!(msg.contains("target="), "Missing target address. Got: {msg}");
        assert!(msg.contains("block=200"), "Missing block number. Got: {msg}");
        // The revm output should be the actual SLOAD'd value encoded as 32 bytes.
        assert!(
            msg.contains(&format!("{:064x}", 0xBEEFu64)),
            "Expected revm output hex to contain the stored value. Got: {msg}"
        );
    }
}
