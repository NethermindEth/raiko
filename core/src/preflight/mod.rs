use crate::{
    interfaces::{RaikoError, RaikoResult},
    preflight::util::get_grandparent_timestamp,
    provider::{rpc::RpcBlockDataProvider, BlockDataProvider},
};
use alethia_reth_primitives::TaikoTxEnvelope;
use futures::future::join_all;
use raiko_lib::{
    builder::{create_mem_db, RethBlockBuilder},
    consts::ChainSpec,
    input::{
        BlobProofType, BlockProposedFork, GuestBatchInput, GuestInput, TaikoGuestInput,
        TaikoProverData,
    },
    l1_precompiles::{
        clear_l1_rpc_fetcher, clear_l1_rpc_served_calls, clear_l1_staticcall_rpc_fetcher,
        clear_l1_staticcall_rpc_served_calls, prepare_l1_precompiles_for_execution,
        set_l1_rpc_fetcher, set_l1_staticcall_rpc_fetcher, take_l1_rpc_served_calls,
        take_l1_staticcall_rpc_served_calls,
    },
    proof_type::ProofType,
    utils::txs::{generate_transactions, generate_transactions_for_batch_blocks},
    Measurement,
};
use tracing::{debug, info};

use util::{
    extend_l1_headers_for_l1staticcall_witnesses, fetch_l1_proofs_for_rpc_served_calls,
    fetch_l1_staticcall_witnesses, get_batch_blocks_and_parent_data, get_block_and_parent_data,
    make_l1_staticcall_rpc_fetcher, prepare_taiko_chain_batch_input, prepare_taiko_chain_input,
};

pub use util::{
    parse_l1_batch_proposal_tx_for_pacaya_fork, parse_l1_batch_proposal_tx_for_shasta_fork,
};

pub(crate) mod util;

/// Run the L1 precompile discovery + fetch pass for a single GuestInput that has already
/// had its witness-driven `parent_state_trie`, `parent_storage`, `contracts`, and
/// `ancestor_headers` populated. Mutates `input` in place to add `l1_storage_proofs`,
/// `l1_staticcall_witnesses`, and `l1_headers`.
///
/// Architecture (post PR #58 — debug_executionWitness-based preflight):
///
/// 1. Build a temp `MemDb` from the witness data (the same data the host's verification
///    re-execution will use later).
/// 2. Set the `(anchor, l1_max_anchor)` precompile context — required for the precompile's
///    block-range check to pass during discovery.
/// 3. Install L1SLOAD + L1STATICCALL RPC fetchers pointed at the L1 RPC. The fetchers
///    record served calls as side-effects; serving the actual L1 data is what makes the
///    L2 re-execution succeed during discovery.
/// 4. Re-execute the L2 block once (discovery pass).
/// 5. Take the served-call lists.
/// 6. Clear the fetchers — the verification re-execution must hit the cache, not RPC.
/// 7. Fetch L1 storage proofs (`eth_getProof`) and L1STATICCALL execution witnesses
///    (`debug_executionWitnessCall`) from the L1 RPC for each served call.
/// 8. Populate `input.l1_storage_proofs`, `input.l1_staticcall_witnesses`, `input.l1_headers`.
///
/// At the end, the GuestInput carries everything the verification re-execution and the ZK
/// guest need to populate the L1 precompile cache deterministically.
/// Run the L1 precompile discovery for one input. The caller supplies `pool_txs` (the
/// transaction list this block actually executes) — for a single-block path that comes from
/// `generate_transactions(...)`, for a batch path it comes from
/// `generate_transactions_for_batch_blocks(...)`. We must use the caller-supplied list and
/// not re-derive it here, because realtime stores its tx data in the *batch-level*
/// `data_sources` (per-block `taiko.tx_data` is empty), and re-deriving via
/// `generate_transactions` would feed `decode_blob_data` an empty buffer and panic.
async fn discover_and_fetch_l1_precompile_data(
    input: &mut GuestInput,
    pool_txs: Vec<TaikoTxEnvelope>,
    l1_chain_spec: &ChainSpec,
) -> RaikoResult<()> {
    if !input.chain_spec.is_taiko() {
        return Ok(());
    }

    // Discovery + harvest is the only stage that needs the synchronous L1SLOAD lock — it
    // mutates the global precompile context and the served-calls list. The lock is held in
    // a non-async block so the `MutexGuard` (which is `!Send`) never crosses an `await`.
    // Subsequent L1 RPC fetches happen *after* the guard drops; the cache itself isn't read
    // until the host's verification re-execution, which re-acquires the lock through
    // `prepare_l1_precompiles_for_execution`.
    let l1_rpc_url = l1_chain_spec.rpc.clone();
    let l1_max_anchor_block_number = input.taiko.l1_header.number;

    let (l1sload_served_calls, l1staticcall_served_calls) = {
        let _l1_precompile_guard = prepare_l1_precompiles_for_execution(input)
            .map_err(|e| RaikoError::Preflight(format!("L1 precompile prep (discovery): {e}")))?;
        clear_l1_rpc_served_calls();
        clear_l1_staticcall_rpc_served_calls();

        // Install L1 RPC fetchers.
        let parsed_url = reqwest::Url::parse(&l1_rpc_url)
            .map_err(|e| RaikoError::Preflight(format!("invalid L1 RPC URL: {e}")))?;
        let l1_client = alloy_rpc_client::ClientBuilder::default().http(parsed_url);
        let handle = tokio::runtime::Handle::current();
        {
            let l1_client = l1_client.clone();
            let handle = handle.clone();
            set_l1_rpc_fetcher(move |address, storage_key, block_number| {
                let client = l1_client.clone();
                let handle = handle.clone();
                tokio::task::block_in_place(move || {
                    handle.block_on(async move {
                        let block_id = alloy_rpc_types::BlockId::Number(block_number.into());
                        let value: alloy_primitives::U256 = client
                            .request("eth_getStorageAt", (address, storage_key, Some(block_id)))
                            .await
                            .map_err(|e| format!("eth_getStorageAt failed: {e}"))?;
                        Ok(alloy_primitives::B256::from(value.to_be_bytes::<32>()))
                    })
                })
            });
        }
        {
            let l1_staticcall_fetcher =
                make_l1_staticcall_rpc_fetcher(l1_rpc_url.clone(), handle)?;
            set_l1_staticcall_rpc_fetcher(l1_staticcall_fetcher);
        }

        // Discovery re-execution. We clone `input` because RethBlockBuilder consumes the
        // GuestInput; the verification re-execution later re-creates its own builder from
        // the original input.
        let discovery_input = input.clone();
        let mut discovery_input_for_db = input.clone();
        let db = create_mem_db(&mut discovery_input_for_db).map_err(|e| {
            RaikoError::Preflight(format!("create_mem_db (discovery) failed: {e}"))
        })?;
        let mut discovery_builder = RethBlockBuilder::new(discovery_input, db);
        if let Err(e) = discovery_builder.execute_transactions(pool_txs, false) {
            // Don't propagate — discovery's only job is to harvest served calls. A failure
            // here means some L1 RPC call errored mid-execution; we still take whatever was
            // served so the user gets a clear "RPC unreachable" or similar at fetch time.
            tracing::warn!(
                "preflight discovery: L2 re-execution returned error \
                 (continuing to fetch what was served): {e}"
            );
        }

        // Take served calls, clear fetchers (so the host's verification re-execution must
        // hit the cache, not RPC), then drop the guard.
        let l1sload = take_l1_rpc_served_calls();
        let l1staticcall = take_l1_staticcall_rpc_served_calls();
        clear_l1_rpc_fetcher();
        clear_l1_staticcall_rpc_fetcher();
        (l1sload, l1staticcall)
    };

    info!(
        "preflight discovery: L1SLOAD served={}, L1STATICCALL served={}",
        l1sload_served_calls.len(),
        l1staticcall_served_calls.len(),
    );

    // No L1 calls observed → leave input unchanged.
    if l1sload_served_calls.is_empty() && l1staticcall_served_calls.is_empty() {
        return Ok(());
    }

    let l1_provider = RpcBlockDataProvider::new(&l1_rpc_url).await?;

    // Step 7a: L1SLOAD proofs + their L1 ancestor headers.
    if !l1sload_served_calls.is_empty() {
        let collection = fetch_l1_proofs_for_rpc_served_calls(
            &l1_provider,
            &l1sload_served_calls,
            l1_max_anchor_block_number,
        )
        .await?;
        input.l1_storage_proofs = collection.proofs;
        input.l1_headers = collection.l1_headers;
    }

    // Step 7b + 8: L1STATICCALL witnesses (and extend l1_headers if needed).
    if !l1staticcall_served_calls.is_empty() {
        input.l1_staticcall_witnesses =
            fetch_l1_staticcall_witnesses(&l1_rpc_url, &l1staticcall_served_calls).await?;
        extend_l1_headers_for_l1staticcall_witnesses(input, &l1_provider, l1_max_anchor_block_number)
            .await?;
    }

    Ok(())
}

pub struct PreflightData {
    pub block_number: u64,
    pub l1_chain_spec: ChainSpec,
    pub l1_inclusion_block_number: u64,
    pub taiko_chain_spec: ChainSpec,
    pub prover_data: TaikoProverData,
    pub blob_proof_type: BlobProofType,
    pub proof_type: ProofType,
}

pub struct BatchPreflightData {
    pub batch_id: u64,
    pub block_numbers: Vec<u64>,
    pub l1_inclusion_block_number: u64,
    pub l1_chain_spec: ChainSpec,
    pub taiko_chain_spec: ChainSpec,
    pub prover_data: TaikoProverData,
    pub blob_proof_type: BlobProofType,
    /// Cached event data to avoid duplicate RPC calls
    pub cached_event_data: Option<raiko_lib::input::BlockProposedFork>,
    pub proof_type: ProofType,
}

impl PreflightData {
    pub fn new(
        block_number: u64,
        l1_inclusion_block_number: u64,
        l1_chain_spec: ChainSpec,
        taiko_chain_spec: ChainSpec,
        prover_data: TaikoProverData,
        blob_proof_type: BlobProofType,
        proof_type: ProofType,
    ) -> Self {
        Self {
            block_number,
            l1_chain_spec,
            l1_inclusion_block_number,
            taiko_chain_spec,
            prover_data,
            blob_proof_type,
            proof_type,
        }
    }
}

pub async fn preflight<BDP: BlockDataProvider>(
    provider: BDP,
    PreflightData {
        block_number,
        l1_chain_spec,
        taiko_chain_spec,
        prover_data,
        blob_proof_type,
        proof_type,
        l1_inclusion_block_number,
    }: PreflightData,
) -> RaikoResult<GuestInput> {
    let measurement = Measurement::start("Fetching block data...", false);

    let (block, parent_block) = get_block_and_parent_data(&provider, block_number).await?;

    let taiko_guest_input = if taiko_chain_spec.is_taiko() {
        prepare_taiko_chain_input(
            &l1_chain_spec,
            &taiko_chain_spec,
            block_number,
            (l1_inclusion_block_number != 0).then_some(l1_inclusion_block_number),
            &block,
            prover_data,
            &blob_proof_type,
        )
        .await?
    } else {
        // For Ethereum blocks we just convert the block transactions in a tx_list
        // so that we don't have to supports separate paths.
        TaikoGuestInput::try_from(block.body.transactions.clone())
            .map_err(|e| RaikoError::Conversion(e.0))?
    };
    measurement.stop();
    info!("preflight: guest input done");

    let parent_header: reth_primitives::Header = parent_block.header.inner.clone();

    info!("preflight: parent header done");

    // Create the guest input
    let input = GuestInput {
        block: block.clone(),
        parent_header,
        chain_spec: taiko_chain_spec.clone(),
        taiko: taiko_guest_input,
        ..Default::default()
    };

    // for TDX proofs, we avoid rebuilding the state trie and re-executing the
    // block as the node execution is trusted
    if proof_type == ProofType::Tdx {
        info!("preflight: skipping re-execution since TDX proof");
        return Ok(input);
    }

    // Fetch execution witness from the L2 node
    let witness = provider
        .execution_witness(block_number)
        .await
        .ok_or_else(|| {
            RaikoError::Preflight("execution witness not supported by provider".to_owned())
        })?
        .map_err(|e| RaikoError::Preflight(format!("execution witness failed: {e}")))?;

    info!("preflight: using execution witness path");
    let measurement = Measurement::start("Building tries from witness...", true);
    let (parent_state_trie, parent_storage, contracts, ancestor_headers) =
        raiko_lib::primitives::mpt::witness_to_tries(
            input.parent_header.state_root,
            witness.state,
            witness.keys,
            witness.codes,
            witness.headers,
        )?;
    measurement.stop();

    let input = GuestInput {
        parent_state_trie,
        parent_storage,
        contracts,
        ancestor_headers,
        ..input
    };

    info!("preflight: witness-based input done");

    // L1 precompile discovery + witness collection. The L2 block witness fetched above
    // covers L2 state but not the L1 data the L1SLOAD/L1STATICCALL precompiles fetched at
    // L2 execution time. We re-execute the L2 block locally with L1 RPC fetchers installed
    // to discover what L1 data is needed, then fetch verifiable proofs/witnesses from L1.
    //
    // The single-block `preflight()` entry point doesn't support Shasta or RealTime forks
    // (see `prepare_taiko_chain_input` in util.rs) — those go through `batch_preflight`
    // instead. So `generate_transactions(...)` here is safe (Ontake/Pacaya/Hekla pull from
    // `taiko.tx_data` which is non-empty for those forks).
    let mut input = input;
    let pool_txs = generate_transactions(
        &input.chain_spec,
        &input.taiko.block_proposed,
        &input.taiko.tx_data,
        &input.taiko.anchor_tx,
    );
    discover_and_fetch_l1_precompile_data(&mut input, pool_txs, &l1_chain_spec).await?;

    Ok(input)
}

pub async fn batch_preflight<BDP: BlockDataProvider>(
    provider: BDP,
    BatchPreflightData {
        batch_id,
        block_numbers,
        l1_chain_spec,
        taiko_chain_spec,
        prover_data,
        blob_proof_type,
        l1_inclusion_block_number,
        cached_event_data,
        proof_type,
    }: BatchPreflightData,
) -> RaikoResult<GuestBatchInput> {
    let measurement = Measurement::start("Fetching block data...", false);

    let all_block_parent_pairs =
        get_batch_blocks_and_parent_data(&provider, &block_numbers).await?;
    let (l2_grandparent_header, block_parent_pairs) = if block_numbers[0] == 1 {
        (None, all_block_parent_pairs)
    } else {
        // The first pair's parent is the grandparent (first block's parent's parent)
        // Extract it and remove the first pair since we don't need it for subsequent processing
        debug!("all_block_parent_pairs: {:?}", all_block_parent_pairs);
        (
            all_block_parent_pairs
                .first()
                .map(|(_, parent_block)| parent_block.header.clone().try_into().unwrap()),
            all_block_parent_pairs.into_iter().skip(1).collect(),
        )
    };

    let l2_block_numbers: Vec<(u64, Option<u64>)> = block_numbers
        .iter()
        .map(|&block_number| (block_number, None))
        .collect::<Vec<(u64, Option<u64>)>>();
    info!(
        "batch preflight {} l2_block_numbers: {:?} to {:?}.",
        l2_block_numbers.len(),
        l2_block_numbers.first(),
        l2_block_numbers.last(),
    );
    let all_prove_blocks = block_parent_pairs
        .iter()
        .map(|(block, _)| block.clone())
        .collect::<Vec<_>>();
    let taiko_guest_batch_input = if taiko_chain_spec.is_taiko() {
        prepare_taiko_chain_batch_input(
            &l1_chain_spec,
            &taiko_chain_spec,
            l1_inclusion_block_number,
            batch_id,
            &all_prove_blocks,
            prover_data,
            &blob_proof_type,
            cached_event_data,
            l2_grandparent_header,
        )
        .await?
    } else {
        return Err(RaikoError::Preflight(
            "Batch preflight is only used for Taiko chains".to_owned(),
        ));
    };
    measurement.stop();

    debug!("proven (block, parent) pairs: {:?}", block_parent_pairs);

    let mock_guest_batch_input = GuestBatchInput {
        inputs: block_parent_pairs
            .iter()
            .map(|(block, parent_block)| GuestInput {
                block: block.clone(),
                parent_header: parent_block.header.clone().try_into().unwrap(),
                chain_spec: taiko_chain_spec.clone(),
                ..Default::default()
            })
            .collect(),
        taiko: taiko_guest_batch_input.clone(),
    };

    // distribute txs to each block
    let pool_txs_list: Vec<(Vec<TaikoTxEnvelope>, bool)> =
        generate_transactions_for_batch_blocks(&mock_guest_batch_input);

    assert_eq!(block_parent_pairs.len(), pool_txs_list.len());

    // Step 1: Build all GuestInputs sequentially (cheap, no I/O — just grandparent_timestamp tracking)
    if block_parent_pairs.is_empty() {
        return Err(RaikoError::Preflight(
            "No blocks to prove in batch".to_owned(),
        ));
    }
    let first_block_number = block_parent_pairs[0].0.header.number;
    let mut grandparent_timestamp =
        get_grandparent_timestamp(&provider, first_block_number).await?;

    let mut base_inputs: Vec<GuestInput> = Vec::with_capacity(block_parent_pairs.len());
    for ((prove_block, parent_block), (_pool_txs, is_force_inclusion)) in
        block_parent_pairs.iter().zip(pool_txs_list.iter())
    {
        let parent_header: reth_primitives::Header = (*parent_block.header).clone();
        let anchor_tx = prove_block.body.transactions.first().unwrap().clone();
        let taiko_input = TaikoGuestInput {
            l1_header: taiko_guest_batch_input.l1_header.clone(),
            tx_data: Vec::new(),
            anchor_tx: Some(anchor_tx),
            block_proposed: taiko_guest_batch_input.batch_proposed.clone(),
            prover_data: taiko_guest_batch_input.prover_data.clone(),
            blob_commitment: None,
            blob_proof: None,
            blob_proof_type: taiko_guest_batch_input.data_sources[0]
                .blob_proof_type
                .clone(),
            extra_data: match taiko_guest_batch_input.batch_proposed {
                BlockProposedFork::Shasta(_) => Some(*is_force_inclusion),
                _ => None,
            },
            grandparent_timestamp,
        };

        grandparent_timestamp = Some(parent_header.timestamp);

        base_inputs.push(GuestInput {
            block: prove_block.clone(),
            parent_header,
            chain_spec: taiko_chain_spec.clone(),
            taiko: taiko_input,
            ..Default::default()
        });
    }

    // For TDX proofs, skip witness fetching entirely
    if proof_type == ProofType::Tdx {
        info!("batch_preflight: skipping re-execution since TDX proof");
        return Ok(GuestBatchInput {
            inputs: base_inputs,
            taiko: taiko_guest_batch_input,
        });
    }

    // Step 2: Fetch all witnesses concurrently
    let witness_block_numbers: Vec<u64> = base_inputs
        .iter()
        .map(|input| input.block.header.number)
        .collect();
    let witness_futures: Vec<_> = witness_block_numbers
        .iter()
        .map(|&block_number| {
            let provider = &provider;
            async move {
                provider
                    .execution_witness(block_number)
                    .await
                    .ok_or_else(|| {
                        RaikoError::Preflight(format!(
                            "execution witness not supported for block {block_number}"
                        ))
                    })?
                    .map_err(|e| {
                        RaikoError::Preflight(format!(
                            "execution witness failed for block {block_number}: {e}"
                        ))
                    })
            }
        })
        .collect();
    let witnesses: Vec<RaikoResult<_>> = join_all(witness_futures).await;

    // Step 3: Apply witness data to each input
    let mut final_inputs: Vec<GuestInput> = Vec::with_capacity(base_inputs.len());
    for (input, witness_result) in base_inputs.into_iter().zip(witnesses) {
        let witness = witness_result?;
        let block_number = input.block.header.number;
        info!("batch_preflight: block {block_number} using execution witness");

        let (parent_state_trie, parent_storage, contracts, ancestor_headers) =
            raiko_lib::primitives::mpt::witness_to_tries(
                input.parent_header.state_root,
                witness.state,
                witness.keys,
                witness.codes,
                witness.headers,
            )?;

        final_inputs.push(GuestInput {
            parent_state_trie,
            parent_storage,
            contracts,
            ancestor_headers,
            ..input
        });
    }

    // L1 precompile discovery + witness collection — per-block, mirrors the single-block
    // path above. Each input in the batch gets its own (anchor, l1_max_anchor) context and
    // its own served-call set, so we run discovery sequentially. The global precompile lock
    // serializes the cache state across the per-block iterations.
    //
    // Reuse the per-block `pool_txs_list` we already computed via
    // `generate_transactions_for_batch_blocks` (which decodes from the *batch-level*
    // `data_sources` — required for Shasta + RealTime where per-block `taiko.tx_data` is
    // empty). Calling `generate_transactions` per-block here would panic in
    // `decode_blob_data` for those forks.
    let final_with_pool_txs = final_inputs
        .iter_mut()
        .zip(pool_txs_list.iter())
        .collect::<Vec<_>>();
    for (input, (pool_txs, _is_force_inclusion)) in final_with_pool_txs {
        // Prepend the anchor tx — RethBlockBuilder.execute_transactions expects the anchor
        // first, matching `Raiko::execute_transaction_batch` in core/src/lib.rs.
        let mut full_pool_txs = vec![input.taiko.anchor_tx.clone().ok_or_else(|| {
            RaikoError::Preflight("missing anchor tx in batch input".to_string())
        })?];
        full_pool_txs.extend_from_slice(pool_txs.as_slice());
        discover_and_fetch_l1_precompile_data(input, full_pool_txs, &l1_chain_spec).await?;
    }

    Ok(GuestBatchInput {
        inputs: final_inputs,
        taiko: taiko_guest_batch_input,
    })
}

#[cfg(test)]
mod test {
    use ethers_core::types::Transaction;
    use raiko_lib::{
        consts::{Network, SupportedChainSpecs},
        utils::txs::decode_transactions,
    };

    use crate::preflight::util::{blob_to_bytes, block_time_to_block_slot};

    #[test]
    fn test_new_blob_decode() {
        let valid_blob_str = "\
            01000004b0f904adb8b502f8b283028c59188459682f008459682f028286b394\
            006700100000000000000000000000000001009980b844a9059cbb0000000000\
            0000000000000001670010000000000000000000000000000100990000000000\
            000000000000000000000000000000000000000000000000000001c080a0af40\
            093afa19e4b7256a209c71a902d33985c5655e580d5fbf36815e290b623177a0\
            19d4b4ccaa5497a47845016680c128b63e74e9d6a9756ebdeb2f78a65e0fa120\
            0001f802f901f483028c592e8459682f008459682f02832625a0941670010000\
            0b000000000000000000000000000280b90184fa233d0c000000000000000000\
            0000000000000000000000000000000000000000000000200000000000000000\
            000000000000000000000000000000000000000000007e7e0000000000000000\
            0000000014dc79964da2c08b23698b3d3cc7ca32193d99550000000000000000\
            0000000014dc79964da2c08b23698b3d3cc7ca32193d99550000000000000000\
            0000000000016700100000000000000000000000000001009900000000000000\
            0000000000000000000000000000000000000000000000000100000000000000\
            000000000000000000000000000000000000000000002625a000000000000000\
            0000000000000000000000000000000000000000000000000000000000000000\
            000000000000976ea74026e726554db657fa54763abd0c3a0aa9000000000000\
            0000000000000000000000000000000000000000000000000120000000000000\
            220000000000000000000000000000000000000000000000001243726f6e4a6f\
            102053656e64546f6b656e730000000000000000000000000000c080a0a99edd\
            2b13d5436cb0fe71b2ea4e69c2292fdc682ae54fe702cc36d6634dd0ba85a057\
            119f9297ca5ebd5402bd886405fe3aa8f8182438a9e56c1ef2a1ec0ae4a0acb9\
            00f802f901f483028c592f8459682f008459682f02832625a094167001000000\
            000000000000000000000000000280b90184fa233d0c00000000000000000000\
            0000000000000000000000000000000000000000000020000000000000000000\
            0000000000000000000000000000000000000000007e7e000000000000000000\
            00000014dc79964da2c08b23698b3d3cc7ca32193d9955000000000000000000\
            00000014dc79964da2c08b23698b3d3cc7ca32193d9955000000000000000000\
            0000000001670010000000000000000000000000000100990000000000000000\
            0000000000000000000000000000000000000000000000010000000000000000\
            0000000000000000000000000000000000000000002625a00000000000000000\
            0000000000000000000000000000000000000000000000000000000000000000\
            0000000000976ea74026e726554db657fa54763abd0c3a0aa900000000000000\
            0000000000000000000000000000000000000000000000012000000000000000\
            2000000000000000000000000000000000000000000000001243726f6e4a6f62\
            0053656e64546f6b656e730000000000000000000000000000c080a08f0a9757\
            35d78526f1339c69c2ed02df7a6d7cded10c74fb57398c11c1420526c2a0047f\
            003054d3d75d33120020872b6d5e0a4a05e47c50179bb9a8b866b7fb71b30000\
            0000000000000000000000000000000000000000000000000000000000000000\
            0000000000000000000000000000000000000000000000000000000000000000\
            0000000000000000000000000000000000000000000000000000000000000000\
            0000000000000000000000000000000000000000000000000000000000000000\
            0000000000000000000000000000000000000000000000000000000000000000\
            00000000000000000000000000000000";

        let mut blob_str = String::with_capacity(262_144);
        blob_str.push_str(&valid_blob_str);
        if blob_str.len() < 262_144 {
            blob_str.extend(std::iter::repeat('0').take(262_144 - blob_str.len()));
        }

        let dec_blob = blob_to_bytes(&blob_str);
        println!("dec blob tx len: {:?}", dec_blob.len());
        let txs = decode_transactions(&dec_blob);
        println!("dec blob tx: {txs:?}");
    }

    #[ignore]
    #[test]
    fn test_slot_block_num_mapping() {
        let chain_spec = SupportedChainSpecs::default()
            .get_chain_spec(&Network::TaikoA7.to_string())
            .unwrap();
        let expected_slot = 1000u64;
        let second_per_slot = 12u64;
        let block_time = chain_spec.genesis_time + expected_slot * second_per_slot;
        let block_num =
            block_time_to_block_slot(block_time, chain_spec.genesis_time, second_per_slot)
                .expect("block time to slot failed");
        assert_eq!(block_num, expected_slot);

        assert!(block_time_to_block_slot(
            chain_spec.genesis_time - 10,
            chain_spec.genesis_time,
            second_per_slot
        )
        .is_err());
    }

    #[ignore]
    #[test]
    fn json_to_ethers_blob_tx() {
        let response = "{
            \"blockHash\":\"0xa61eea0256aa361dfd436be11b0e276470413fbbc34b3642fbbf3b5d8d72f612\",
		    \"blockNumber\":\"0x4\",
		    \"from\":\"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266\",
		    \"gas\":\"0xf4240\",
		    \"gasPrice\":\"0x5e92e74e\",
		    \"maxFeePerGas\":\"0x8b772ea6\",
		    \"maxPriorityFeePerGas\":\"0x3b9aca00\",
		    \"maxFeePerBlobGas\":\"0x2\",
		    \"hash\":\"0xdb3b11250a2332cc4944fa8022836bd32da43c34d4f2e9e1b246cfdbc5b4c60e\",
		    \"input\":\"0x11762da2\",
		    \"nonce\":\"0x1\",
		    \"to\":\"0x5fbdb2315678afecb367f032d93f642f64180aa3\",
		    \"transactionIndex\":\"0x0\",
		    \"value\":\"0x0\",
		    \"type\":\"0x3\",
            \"accessList\":[],
		    \"chainId\":\"0x7e7e\",
            \"blobVersionedHashes\":[\"0x012d46373b7d1f53793cd6872e40e801f9af6860ecbdbaa2e28df25937618c6f\",\"0x0126d296b606f85b775b12b8b4abeb3bdb88f5a50502754d598537ae9b7fb947\"],
            \"v\":\"0x0\",
		    \"r\":\"0xaba289efba8ef610a5b3b70b72a42fe1916640f64d7112ec0b89087bbc8fff5f\",
		    \"s\":\"0x1de067d69b79d28d0a3bd179e332c85b93cedbd299d9e205398c073a59633dcf\",
		    \"yParity\":\"0x0\"
        }";
        let tx: Transaction = serde_json::from_str(response).unwrap();
        println!("tx: {tx:?}");
    }
}
