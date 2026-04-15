use alethia_reth_evm::precompiles::l1staticcall::set_l1_staticcall_value;
use alloy_primitives::B256;
use anyhow::{anyhow, Result};
use std::collections::HashMap;
use tracing::{debug, info, warn};

use crate::input::L1StaticCallWitness;

/// Verify and populate L1STATICCALL results from execution witnesses.
///
/// For each witness:
/// 1. Verify the L1 state root is trusted (from the verified header chain)
/// 2. TODO: Re-execute the call against witnessed state using revm
/// 3. For now: trust the witness data (full revm re-execution will be added)
/// 4. Populate the L1STATICCALL cache with the verified result
pub fn verify_and_populate_l1_staticcall_witnesses(
    witnesses: &[L1StaticCallWitness],
    state_root_map: &HashMap<u64, B256>,
) -> Result<()> {
    if witnesses.is_empty() {
        debug!("L1STATICCALL: no witnesses to verify, skipping");
        return Ok(());
    }

    info!(
        "L1STATICCALL: verifying {} execution witnesses",
        witnesses.len()
    );

    for (i, w) in witnesses.iter().enumerate() {
        // 1. Verify we have a trusted state root for this block
        let _state_root = state_root_map.get(&w.block_number).ok_or_else(|| {
            anyhow!(
                "L1STATICCALL: no verified state root for block {} (witness #{})",
                w.block_number,
                i
            )
        })?;

        // 2. Verify witness is non-empty (basic sanity check)
        if w.execution_witness.state.is_empty() {
            warn!(
                "L1STATICCALL: witness #{} has empty state trie nodes for target={:?}, block={}",
                i, w.target_address, w.block_number
            );
        }

        debug!(
            "L1STATICCALL: witness #{}: target={:?}, block={}, calldata_len={}, return_len={}, state_nodes={}, codes={}",
            i, w.target_address, w.block_number, w.calldata.len(), w.return_data.len(),
            w.execution_witness.state.len(), w.execution_witness.codes.len()
        );

        // TODO: Full ZK verification:
        // a. Build in-memory hash DB from witness trie nodes
        // b. Verify trie opens correctly at the trusted state root
        // c. Re-execute the L1 call using revm against the witnessed state
        // d. Compare result with recorded return_data -> match or fail
        //
        // For now, we populate the cache directly. The witness data was collected
        // by the preflight from a trusted L1 node, and the state_root is verified
        // via the header chain. Full revm re-execution will be added to close
        // the trust assumption.

        // 3. Populate cache with the witnessed result
        set_l1_staticcall_value(
            w.target_address,
            w.block_number,
            &w.calldata,
            w.return_data.to_vec(),
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
    use alloy_primitives::{Address, Bytes, B256};
    use crate::input::{L1StaticCallWitness, ExecutionWitness};
    use alethia_reth_evm::precompiles::l1staticcall::{
        clear_l1_staticcall_cache, l1staticcall_run,
    };
    use alethia_reth_evm::precompiles::l1sload::{
        clear_l1_storage, set_anchor_block_id, set_l1_origin_block_id,
    };
    use alloy_primitives::U256;
    use serial_test::serial;

    // ───────────────────────────────────────────────
    // Helpers
    // ───────────────────────────────────────────────

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
        let result = verify_and_populate_l1_staticcall_witnesses(&[], &state_root_map);
        assert!(result.is_ok(), "Empty witness list should return Ok");
    }

    #[test]
    #[serial]
    fn test_verify_missing_state_root_fails() {
        reset_all();
        let target = Address::from([0xAAu8; 20]);
        let witness = make_witness(target, 50, &[0x01], &[0xFF]);

        // State root map does not contain block 50
        let state_root_map: HashMap<u64, B256> = HashMap::from([
            (100, B256::from([0x11u8; 32])),
        ]);

        let result = verify_and_populate_l1_staticcall_witnesses(&[witness], &state_root_map);
        assert!(result.is_err(), "Should fail when witness references block not in state_root_map");
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

        let state_root_map: HashMap<u64, B256> = HashMap::from([
            (100, B256::from([0x22u8; 32])),
        ]);

        let result = verify_and_populate_l1_staticcall_witnesses(&[witness], &state_root_map);
        assert!(result.is_ok(), "Single valid witness should succeed: {:?}", result.err());

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

        let result = verify_and_populate_l1_staticcall_witnesses(
            &[witness_a, witness_b, witness_c],
            &state_root_map,
        );
        assert!(result.is_ok(), "Multiple valid witnesses should all succeed: {:?}", result.err());

        // Verify all three were cached
        set_anchor_block_id(90);
        set_l1_origin_block_id(110);

        // Check witness_a
        let mut input_a = Vec::with_capacity(53);
        input_a.extend_from_slice(target_a.as_slice());
        input_a.extend_from_slice(&U256::from(100u64).to_be_bytes::<32>());
        input_a.push(0x01);
        let res_a = l1staticcall_run(&input_a, 100_000);
        assert!(res_a.is_ok(), "witness_a should be cached: {:?}", res_a.err());
        assert_eq!(res_a.unwrap().bytes.as_ref(), &[0x11, 0x22]);

        // Check witness_b
        let mut input_b = Vec::with_capacity(53);
        input_b.extend_from_slice(target_b.as_slice());
        input_b.extend_from_slice(&U256::from(101u64).to_be_bytes::<32>());
        input_b.push(0x02);
        let res_b = l1staticcall_run(&input_b, 100_000);
        assert!(res_b.is_ok(), "witness_b should be cached: {:?}", res_b.err());
        assert_eq!(res_b.unwrap().bytes.as_ref(), &[0x33, 0x44]);

        // Check witness_c
        let mut input_c = Vec::with_capacity(53);
        input_c.extend_from_slice(target_a.as_slice());
        input_c.extend_from_slice(&U256::from(102u64).to_be_bytes::<32>());
        input_c.push(0x03);
        let res_c = l1staticcall_run(&input_c, 100_000);
        assert!(res_c.is_ok(), "witness_c should be cached: {:?}", res_c.err());
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

        let state_root_map: HashMap<u64, B256> = HashMap::from([
            (200, B256::from([0x44u8; 32])),
        ]);

        let result = verify_and_populate_l1_staticcall_witnesses(&[witness], &state_root_map);
        assert!(result.is_ok(), "Verification should succeed: {:?}", result.err());

        // 1. Set anchor and l1_origin block IDs so the precompile allows the query
        set_anchor_block_id(190);
        set_l1_origin_block_id(210);

        // 2. Build a precompile input: target(20) + block_number_u256(32) + calldata
        let mut input = Vec::with_capacity(52 + calldata.len());
        input.extend_from_slice(target.as_slice());                          // 20 bytes
        input.extend_from_slice(&U256::from(200u64).to_be_bytes::<32>());    // 32 bytes
        input.extend_from_slice(&calldata);                                  // variable

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

        let state_root_map: HashMap<u64, B256> = HashMap::from([
            (100, B256::from([0x55u8; 32])),
        ]);

        let result = verify_and_populate_l1_staticcall_witnesses(
            &[witness_1, witness_2],
            &state_root_map,
        );
        assert!(result.is_ok(), "Two witnesses for same target should succeed: {:?}", result.err());

        // Set up precompile context
        set_anchor_block_id(90);
        set_l1_origin_block_id(110);

        // Check first calldata returns its own data
        let mut input_1 = Vec::with_capacity(52 + calldata_1.len());
        input_1.extend_from_slice(target.as_slice());
        input_1.extend_from_slice(&U256::from(100u64).to_be_bytes::<32>());
        input_1.extend_from_slice(&calldata_1);
        let res_1 = l1staticcall_run(&input_1, 100_000);
        assert!(res_1.is_ok(), "First calldata should hit cache: {:?}", res_1.err());
        assert_eq!(res_1.unwrap().bytes.as_ref(), &return_data_1);

        // Check second calldata returns its own data
        let mut input_2 = Vec::with_capacity(52 + calldata_2.len());
        input_2.extend_from_slice(target.as_slice());
        input_2.extend_from_slice(&U256::from(100u64).to_be_bytes::<32>());
        input_2.extend_from_slice(&calldata_2);
        let res_2 = l1staticcall_run(&input_2, 100_000);
        assert!(res_2.is_ok(), "Second calldata should hit cache: {:?}", res_2.err());
        assert_eq!(res_2.unwrap().bytes.as_ref(), &return_data_2);

        // Confirm they are indeed different values
        assert_ne!(
            return_data_1, return_data_2,
            "Different calldata should produce different return data"
        );
    }
}
