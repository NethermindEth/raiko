use alloy_consensus::Transaction;
use alloy_primitives::{Log as LogStruct, Uint, B256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::{BlockId, Filter, Header, Log, Transaction as AlloyRpcTransaction};
use alloy_sol_types::{SolCall, SolEvent};
use anyhow::{anyhow, bail, Result};
use raiko_lib::{
    anchor::decode_anchor,
    builder::{OptimisticDatabase, RethBlockBuilder},
    clear_line,
    consts::{ChainSpec, TaikoSpecId},
    inplace_print,
    input::{
        ontake::{BlockProposedV2, CalldataTxList},
        pacaya::BatchProposed,
        proposeBlockCall,
        shasta::{Proposed as ShastaProposed, ShastaEventData},
        BlobProofType, BlockProposed, BlockProposedFork, TaikoGuestBatchInput, TaikoGuestInput,
        TaikoProverData,
    },
    utils::shasta_rules::ANCHOR_MAX_OFFSET,
};
use reth_primitives::{Block as RethBlock, TransactionSigned};
use std::iter;
use tracing::{debug, info, instrument, warn};

use crate::{
    interfaces::{L1InclusionData, RaikoError, RaikoResult},
    provider::{db::ProviderDb, rpc::RpcBlockDataProvider, BlockDataProvider},
    require,
};

// Re-export blob utilities
pub use blobs::{
    filter_tx_blob_beacon_with_proof, get_batch_tx_data_with_proofs, get_tx_blob, GetBlobData,
    GetBlobsResponse,
};

pub mod blobs;
pub mod ontake;
pub mod pacaya;
pub mod shasta;

use pacaya::prepare_taiko_chain_batch_input as prepare_taiko_chain_batch_input_pacaya;

use shasta::prepare_taiko_chain_batch_input as prepare_taiko_chain_batch_input_shasta;

/// Optimize data gathering by executing the transactions multiple times so data can be requested in batches
pub async fn execute_txs<'a, BDP>(
    builder: &mut RethBlockBuilder<ProviderDb<'a, BDP>>,
    pool_txs: Vec<reth_primitives::TransactionSigned>,
) -> RaikoResult<()>
where
    BDP: BlockDataProvider,
{
    let max_iterations = 100;
    info!("execute_txs: start");
    for num_iterations in 0.. {
        info!("execute_txs: iteration {num_iterations}");
        inplace_print(&format!("Executing iteration {num_iterations}..."));

        let Some(db) = builder.db.as_mut() else {
            info!("execute_txs: No db in builder before execute_transactions");
            return Err(RaikoError::Preflight("No db in builder".to_owned()));
        };
        db.optimistic = num_iterations + 1 < max_iterations;

        info!("execute_txs: execute_transactions start");
        builder
            .execute_transactions(pool_txs.clone(), num_iterations + 1 < max_iterations)
            .map_err(|e| {
                RaikoError::Preflight(format!("Executing transactions in builder failed: {e}"))
            })?;
        info!("execute_txs: execute_transactions done");

        let Some(db) = builder.db.as_mut() else {
            info!("execute_txs: No db in builder after execute_transactions");
            return Err(RaikoError::Preflight("No db in builder".to_owned()));
        };
        info!("execute_txs: fetch_data start");
        if db.fetch_data().await {
            clear_line();
            info!("State data fetched in {num_iterations} iterations");
            break;
        }
    }

    Ok(())
}

/// Prepare the input for a Taiko chain
pub async fn prepare_taiko_chain_input(
    l1_chain_spec: &ChainSpec,
    taiko_chain_spec: &ChainSpec,
    block_number: u64,
    l1_inclusion_block_number: Option<u64>,
    block: &RethBlock,
    prover_data: TaikoProverData,
    blob_proof_type: &BlobProofType,
) -> RaikoResult<TaikoGuestInput> {
    // Decode the anchor tx to find out which L1 blocks we need to fetch
    let anchor_tx = block
        .body
        .transactions
        .first()
        .ok_or_else(|| RaikoError::Preflight("No anchor tx in the block".to_owned()))?;

    // get anchor block num and state root
    let fork: TaikoSpecId = taiko_chain_spec.active_fork(block.number, block.timestamp)?;
    let (anchor_block_height, anchor_state_root) = match fork {
        TaikoSpecId::SHASTA => {
            unimplemented!("SHASTA fork is not supported yet");
        }
        TaikoSpecId::PACAYA => {
            warn!("pacaya fork does not support prepare_taiko_chain_input for single block");
            return Err(RaikoError::Preflight(
                "pacaya fork does not support prepare_taiko_chain_input for single block"
                    .to_owned(),
            ));
        }
        TaikoSpecId::ONTAKE => ontake::get_anchor_info(anchor_tx)?,
        _ => {
            let anchor_call = decode_anchor(anchor_tx.input())?;
            (anchor_call.l1BlockId, anchor_call.l1StateRoot)
        }
    };

    // // Get the L1 block in which the L2 block was included so we can fetch the DA data.
    // // Also get the L1 state block header so that we can prove the L1 state root.
    let provider_l1 = RpcBlockDataProvider::new(&l1_chain_spec.rpc).await?;

    info!("current taiko chain fork: {fork:?}");

    let (l1_inclusion_block_number, proposal_tx, block_proposed) =
        if let Some(l1_block_number) = l1_inclusion_block_number {
            // Get the block proposal data
            get_block_proposed_event_by_height(
                provider_l1.provider(),
                taiko_chain_spec.clone(),
                l1_block_number,
                block_number,
                fork,
            )
            .await?
        } else {
            // traversal next 64 blocks to get proposal data
            get_block_proposed_event_by_traversal(
                provider_l1.provider(),
                taiko_chain_spec.clone(),
                anchor_block_height,
                block_number,
                fork,
            )
            .await?
        };

    let (l1_inclusion_header, l1_state_header) = get_headers(
        &provider_l1,
        (l1_inclusion_block_number, anchor_block_height),
    )
    .await?;
    assert_eq!(anchor_state_root, l1_state_header.state_root);
    let l1_state_block_hash = l1_state_header.hash;
    let l1_inclusion_block_hash = l1_inclusion_header.hash;
    info!(
        "L1 inclusion block number: {l1_inclusion_block_number:?}, hash: {l1_inclusion_block_hash:?}. L1 state block number: {:?}, hash: {l1_state_block_hash:?}",
        l1_state_header.number,
    );

    // Fetch the tx data from either calldata or blobdata
    let (tx_data, blob_commitment, blob_proof) = if block_proposed.blob_used() {
        let expected_blob_hash = block_proposed.blob_hash();
        let blob_hashes = proposal_tx.blob_versioned_hashes().unwrap_or_default();
        // Get the blob hashes attached to the propose tx and make sure the expected blob hash is in there
        require(
            blob_hashes.contains(&expected_blob_hash),
            &format!(
                "Proposal blobs hash mismatch: {:?} not in {:?}",
                expected_blob_hash, blob_hashes
            ),
        )?;

        get_tx_blob(
            expected_blob_hash,
            l1_inclusion_header.timestamp,
            l1_chain_spec,
            blob_proof_type,
        )
        .await?
    } else {
        match fork {
            TaikoSpecId::SHASTA => {
                unimplemented!("SHASTA fork is not supported yet");
            }
            TaikoSpecId::PACAYA => {
                warn!("pacaya fork does not support prepare_taiko_chain_input for single block");
                return Err(RaikoError::Preflight(
                    "pacaya fork does not support prepare_taiko_chain_input for single block"
                        .to_owned(),
                ));
            }
            TaikoSpecId::ONTAKE => {
                // Get the tx list data directly from the propose block CalldataTxList event
                let (_, CalldataTxList { txList, .. }) = get_calldata_txlist_event(
                    provider_l1.provider(),
                    taiko_chain_spec.clone(),
                    l1_inclusion_block_hash,
                    block_number,
                )
                .await?;
                (txList.to_vec(), None, None)
            }
            _ => {
                // Get the tx list data directly from the propose transaction data
                let proposeBlockCall { txList, .. } =
                    proposeBlockCall::abi_decode(&proposal_tx.input()).map_err(|_| {
                        RaikoError::Preflight("Could not decode proposeBlockCall".to_owned())
                    })?;
                (txList.to_vec(), None, None)
            }
        }
    };

    info!("prepare_taiko_chain_input done");

    // Create the input struct without the block data set
    Ok(TaikoGuestInput {
        l1_header: l1_state_header.inner,
        tx_data,
        anchor_tx: Some(anchor_tx.clone()),
        blob_commitment,
        block_proposed,
        prover_data,
        blob_proof,
        blob_proof_type: blob_proof_type.clone(),
        ..Default::default()
    })
}

// get fork corresponding anchor block height and state root
fn get_anchor_tx_info_by_fork(
    fork: TaikoSpecId,
    anchor_tx: &TransactionSigned,
) -> RaikoResult<(u64, B256)> {
    match fork {
        TaikoSpecId::SHASTA => shasta::get_anchor_info(anchor_tx),
        TaikoSpecId::PACAYA => pacaya::get_anchor_info(anchor_tx),
        TaikoSpecId::ONTAKE => ontake::get_anchor_info(anchor_tx),
        _ => {
            let anchor_call = decode_anchor(anchor_tx.input())?;
            Ok((anchor_call.l1BlockId, anchor_call.l1StateRoot))
        }
    }
    .map_err(|e| RaikoError::Anyhow(e))
}

/// a problem here is that we need to know the fork of the batch proposal tx
/// but in batch mode, there is no block number in proof request
/// so we hard code the fork to pacaya here.
/// return the block numbers of the batch, i.e. [start(lastBlockId - len() + 1), end(lastBlockId)]
pub async fn parse_l1_batch_proposal_tx_for_pacaya_fork(
    l1_chain_spec: &ChainSpec,
    taiko_chain_spec: &ChainSpec,
    l1_inclusion_block_number: u64,
    batch_id: u64,
) -> RaikoResult<(Vec<u64>, BlockProposedFork)> {
    let provider_l1 = RpcBlockDataProvider::new(&l1_chain_spec.rpc).await?;
    let (l1_inclusion_height, _tx, batch_proposed_fork) = get_block_proposed_event_by_height(
        provider_l1.provider(),
        taiko_chain_spec.clone(),
        l1_inclusion_block_number,
        batch_id,
        TaikoSpecId::PACAYA,
    )
    .await?;

    assert!(
        l1_inclusion_block_number == l1_inclusion_height,
        "proposal tx inclusive block != proof_request block"
    );
    if let BlockProposedFork::Pacaya(batch_proposed) = batch_proposed_fork {
        let batch_info = &batch_proposed.info;
        Ok((
            ((batch_info.lastBlockId - (batch_info.blocks.len() as u64 - 1))
                ..=batch_info.lastBlockId)
                .collect(),
            BlockProposedFork::Pacaya(batch_proposed.clone()),
        ))
    } else {
        Err(RaikoError::Preflight(
            "BatchProposedFork is not Pacaya".to_owned(),
        ))
    }
}

/// we actually separate the different fork by using different entry.
/// batch request -> pacaya
/// proposal request -> shasta
/// Returns (block_numbers, event_data) for caching and reuse
pub async fn parse_l1_batch_proposal_tx_for_shasta_fork(
    l1_chain_spec: &ChainSpec,
    taiko_chain_spec: &ChainSpec,
    l1_inclusion_block_number: u64,
    proposal_id: u64,
) -> RaikoResult<(Vec<u64>, BlockProposedFork)> {
    let provider_l1 = RpcBlockDataProvider::new(&l1_chain_spec.rpc).await?;
    let (l1_inclusion_height, _tx, proposal_fork) = get_block_proposed_event_by_height(
        provider_l1.provider(),
        taiko_chain_spec.clone(),
        l1_inclusion_block_number,
        proposal_id,
        TaikoSpecId::SHASTA,
    )
    .await?;

    assert_eq!(
        l1_inclusion_block_number, l1_inclusion_height,
        "proposal tx inclusive block != proof_request block"
    );

    // _proposal_fork is shasta proposal tx, so we can get the lastFinalizedProposalId from it
    match &proposal_fork {
        BlockProposedFork::Shasta(_) => {
            // todo: no way to get l2 block numbers from shasta proposal tx
            Ok((vec![], proposal_fork))
        }
        _ => Err(RaikoError::Preflight(
            "BlockProposedFork is not Shasta".to_owned(),
        )),
    }
}

pub async fn _parse_l1_bond_proposal_tx_for_shasta_fork(
    _l1_chain_spec: &ChainSpec,
    _taiko_chain_spec: &ChainSpec,
    _l1_bond_proposal_block_number: u64,
    _bond_proposal_id: u64,
) -> RaikoResult<B256> {
    unreachable!("bond proposal is not implemented, double check the logic");

    // let provider_l1 = RpcBlockDataProvider::new(&l1_chain_spec.rpc, 0).await?;
    // let (l1_bond_proposal_height, _tx, _) = get_block_proposed_event_by_height(
    //     provider_l1.provider(),
    //     taiko_chain_spec.clone(),
    //     l1_bond_proposal_block_number,
    //     bond_proposal_id,
    //     TaikoSpecId::SHASTA,
    // )
    // .await?;

    // assert_eq!(
    //     l1_bond_proposal_block_number, l1_bond_proposal_height,
    //     "proposal tx inclusive block != proof_request block"
    // );

    // Ok(B256::ZERO)
}

/// Prepare the input for a Taiko chain
pub async fn prepare_taiko_chain_batch_input(
    l1_chain_spec: &ChainSpec,
    taiko_chain_spec: &ChainSpec,
    l1_inclusion_data: L1InclusionData,
    batch_id: u64,
    batch_blocks: &[RethBlock],
    prover_data: TaikoProverData,
    blob_proof_type: &BlobProofType,
    cached_event_data: Option<BlockProposedFork>,
) -> RaikoResult<TaikoGuestBatchInput> {
    // Get the L1 block in which the L2 block was included so we can fetch the DA data.
    // Also get the L1 state block header so that we can prove the L1 state root.
    // Decode the anchor tx to find out which L1 blocks we need to fetch
    let fork = taiko_chain_spec.active_fork(batch_blocks[0].number, batch_blocks[0].timestamp)?;
    let batch_anchor_tx_info = batch_blocks.iter().try_fold(
        Vec::new(),
        |mut acc, block| -> RaikoResult<Vec<(u64, B256)>> {
            let anchor_tx = block
                .body
                .transactions
                .first()
                .ok_or_else(|| RaikoError::Preflight("No anchor tx in the block".to_owned()))?;
            let anchor_info = get_anchor_tx_info_by_fork(fork, anchor_tx)?;
            acc.push(anchor_info);
            Ok(acc)
        },
    )?;

    // Use cached event data if available, otherwise fetch from RPC
    let batch_proposed_fork = if let Some(cached_data) = cached_event_data {
        debug!("Using cached block proposed event data, skipping RPC call");
        cached_data
    } else {
        debug!("No cached event data, fetching from RPC");
        let provider_l1 = RpcBlockDataProvider::new(&l1_chain_spec.rpc).await?;

        match &l1_inclusion_data {
            L1InclusionData::L1InclusionBlockNumber(l1_inclusion_block_number) => {
                let (l1_inclusion_height, _, event_data) = get_block_proposed_event_by_height(
                    provider_l1.provider(),
                    taiko_chain_spec.clone(),
                    *l1_inclusion_block_number,
                    batch_id,
                    fork,
                )
                .await?;

                assert_eq!(*l1_inclusion_block_number, l1_inclusion_height);
                event_data
            }
            L1InclusionData::LimpModeData(limp_mode_data) => {
                limp_mode_data.get_block_proposed_fork()
            }
        }
    };

    match (fork, batch_proposed_fork) {
        (TaikoSpecId::PACAYA, BlockProposedFork::Pacaya(batch_proposed)) => {
            assert!(
                batch_anchor_tx_info.windows(2).all(|w| { w[0] == w[1] }),
                "batch anchor tx info mismatch {batch_anchor_tx_info:?}"
            );

            if l1_inclusion_data.is_limp_mode() {
                return Err(RaikoError::InvalidRequestConfig(
                    "Limp mode is not supported for Pacaya batch input".to_owned(),
                ));
            }
            prepare_taiko_chain_batch_input_pacaya(
                l1_chain_spec,
                taiko_chain_spec,
                l1_inclusion_data.get_l1_inclusion_block_number().unwrap(),
                batch_id,
                prover_data,
                blob_proof_type,
                batch_anchor_tx_info,
                batch_proposed,
            )
            .await
        }
        (TaikoSpecId::SHASTA, BlockProposedFork::Shasta(shasta_event_data)) => {
            assert!(
                batch_anchor_tx_info
                    .windows(2)
                    .all(|w| if w[0].0 == w[1].0 {
                        w[0].1 == w[1].1
                    } else {
                        // if anchor changes, block hash is not zero
                        w[0].0 < w[1].0 && w[0].1 != B256::ZERO && w[1].1 != B256::ZERO
                    }),
                "batch anchor tx info mismatch, {batch_anchor_tx_info:?}"
            );
            prepare_taiko_chain_batch_input_shasta(
                l1_chain_spec,
                taiko_chain_spec,
                l1_inclusion_data,
                batch_id,
                prover_data,
                blob_proof_type,
                batch_anchor_tx_info,
                shasta_event_data,
            )
            .await
        }
        _ => {
            return Err(RaikoError::Preflight(
                "Unsupported BatchProposedFork type".to_owned(),
            ))
        }
    }
}

pub async fn filter_blockchain_event(
    provider: &RootProvider,
    gen_block_event_filter: impl Fn() -> Filter,
) -> Result<Vec<Log>> {
    // Setup the filter to get the relevant events
    let filter = gen_block_event_filter();
    // Now fetch the events
    Ok(provider.get_logs(&filter).await?)
}

pub async fn get_calldata_txlist_event(
    provider: &RootProvider,
    chain_spec: ChainSpec,
    block_hash: B256,
    l2_block_number: u64,
) -> Result<(AlloyRpcTransaction, CalldataTxList)> {
    ontake::get_calldata_txlist_event(provider, chain_spec, block_hash, l2_block_number).await
}

#[derive(Debug)]
pub enum EventFilterConditioin {
    #[allow(dead_code)]
    Hash(B256),
    Height(u64),
    Range((u64, u64)),
}

#[instrument(skip_all)]
pub async fn filter_block_proposed_event(
    provider: &RootProvider,
    chain_spec: ChainSpec,
    filter_condition: EventFilterConditioin,
    block_num_or_batch_id: u64,
    fork: TaikoSpecId,
) -> Result<(u64, AlloyRpcTransaction, BlockProposedFork)> {
    // Get the address that emitted the event
    let l1_address = chain_spec
        .l1_contract
        .get(&fork)
        .ok_or_else(|| anyhow!("L1 contract address not found for fork {fork:?}"))?
        .clone();

    // Get the event signature (value can differ between chains)
    let event_signature = match fork {
        TaikoSpecId::SHASTA => ShastaProposed::SIGNATURE_HASH,
        TaikoSpecId::PACAYA => BatchProposed::SIGNATURE_HASH,
        TaikoSpecId::ONTAKE => BlockProposedV2::SIGNATURE_HASH,
        _ => BlockProposed::SIGNATURE_HASH,
    };

    debug!("filter condition: {:?}", filter_condition);
    debug!("address: {:?}", l1_address);
    debug!("fork: {:?}", fork);
    debug!("event_signature: {:?}", event_signature);

    // Setup the filter to get the relevant events
    let logs = filter_blockchain_event(provider, || match filter_condition {
        EventFilterConditioin::Hash(block_hash) => Filter::new()
            .address(l1_address)
            .at_block_hash(block_hash)
            .event_signature(event_signature),
        EventFilterConditioin::Height(block_number) => Filter::new()
            .address(l1_address)
            .from_block(block_number)
            .to_block(block_number)
            .event_signature(event_signature),
        EventFilterConditioin::Range((from_block_number, to_block_number)) => Filter::new()
            .address(l1_address)
            .from_block(from_block_number)
            .to_block(to_block_number)
            .event_signature(event_signature),
    })
    .await?;

    // Run over the logs returned to find the matching event for the specified L2 block number
    // (there can be multiple blocks proposed in the same block and even same tx)
    for log in logs {
        let Some(log_struct) = LogStruct::new(
            log.address(),
            log.topics().to_vec(),
            log.data().data.clone(),
        ) else {
            bail!("Could not create log")
        };
        let (block_or_batch_id, block_propose_event) = match fork {
            TaikoSpecId::PACAYA => {
                let event = BatchProposed::decode_log(&log_struct)
                    .map_err(|_| RaikoError::Anyhow(anyhow!("Could not decode log")))?;
                (
                    raiko_lib::primitives::U256::from(event.meta.batchId),
                    BlockProposedFork::Pacaya(event.data),
                )
            }
            TaikoSpecId::SHASTA => {
                let event = ShastaProposed::decode_log(&log_struct)
                    .map_err(|_| RaikoError::Anyhow(anyhow!("Could not decode log")))?;

                let mut event_data = ShastaEventData::from_proposal_event(&event.data);

                // let timestamp = log.block_timestamp.unwrap();
                let current_block_number = log.block_number.unwrap();
                let current_block = provider
                    .get_block(BlockId::number(current_block_number))
                    .await?;
                let Some(current_block) = current_block else {
                    bail!("No current block found for the proposal")
                };
                let timestamp = current_block.header.timestamp;

                let origin_block_number = current_block_number - 1;
                let origin_block = provider
                    .get_block_by_number(alloy_rpc_types::BlockNumberOrTag::Number(
                        origin_block_number,
                    ))
                    .await?;
                let Some(origin_block) = origin_block else {
                    bail!("No origin block found for the proposal")
                };
                let origin_block_hash = origin_block.header.hash;
                event_data.proposal.originBlockNumber = Uint::from(origin_block_number);
                event_data.proposal.originBlockHash = origin_block_hash;
                event_data.proposal.timestamp = Uint::from(timestamp);
                event_data.proposal.parentProposalHash = B256::ZERO;
                (
                    raiko_lib::primitives::U256::from(event_data.proposal.id),
                    BlockProposedFork::Shasta(event_data),
                )
            }
            TaikoSpecId::ONTAKE => {
                let event = BlockProposedV2::decode_log(&log_struct)
                    .map_err(|_| RaikoError::Anyhow(anyhow!("Could not decode log")))?;
                (event.blockId, BlockProposedFork::Ontake(event.data))
            }
            _ => {
                let event = BlockProposed::decode_log(&log_struct)
                    .map_err(|_| RaikoError::Anyhow(anyhow!("Could not decode log")))?;
                (event.blockId, BlockProposedFork::Hekla(event.data))
            }
        };

        if block_or_batch_id == raiko_lib::primitives::U256::from(block_num_or_batch_id) {
            let Some(log_tx_hash) = log.transaction_hash else {
                bail!("No transaction hash in the log")
            };
            let tx = provider
                .get_transaction_by_hash(log_tx_hash)
                .await
                .expect("couldn't query the propose tx")
                .expect("Could not find the propose tx");

            let block_propose_event = match block_propose_event {
                BlockProposedFork::Shasta(event_data) => BlockProposedFork::Shasta(event_data),
                _ => block_propose_event,
            };

            return Ok((log.block_number.unwrap(), tx, block_propose_event));
        } else {
            info!("block_or_batch_id: {block_or_batch_id} != block_num_or_batch_id: {block_num_or_batch_id}");
            continue;
        }
    }

    Err(anyhow!(
        "No BlockProposed event found for proposal/batch id {block_num_or_batch_id}."
    ))
}

// pub async fn _get_block_proposed_event_by_hash(
//     provider: &ReqwestProvider,
//     chain_spec: ChainSpec,
//     l1_inclusion_block_hash: B256,
//     l2_block_number: u64,
//     fork: TaikoSpecId,
// ) -> Result<(u64, AlloyRpcTransaction, BlockProposedFork)> {
//     filter_block_proposed_event(
//         provider,
//         chain_spec,
//         EventFilterConditioin::Hash(l1_inclusion_block_hash),
//         l2_block_number,
//         fork,
//     )
//     .await
// }

pub async fn get_block_proposed_event_by_height(
    provider: &RootProvider,
    chain_spec: ChainSpec,
    l1_inclusion_block_number: u64,
    block_num_or_batch_id: u64,
    fork: TaikoSpecId,
) -> Result<(u64, AlloyRpcTransaction, BlockProposedFork)> {
    filter_block_proposed_event(
        provider,
        chain_spec,
        EventFilterConditioin::Height(l1_inclusion_block_number),
        block_num_or_batch_id,
        fork,
    )
    .await
}

const MAX_ANCHOR_BLOCK_RANGE: u64 = 96;

pub async fn get_block_proposed_event_by_traversal(
    provider: &RootProvider,
    chain_spec: ChainSpec,
    l1_anchor_block_number: u64,
    l2_block_number: u64,
    fork: TaikoSpecId,
) -> Result<(u64, AlloyRpcTransaction, BlockProposedFork)> {
    let latest_block_number = provider.get_block_number().await?;
    let range_start = l1_anchor_block_number + 1;
    let range_end = std::cmp::min(
        l1_anchor_block_number + MAX_ANCHOR_BLOCK_RANGE,
        latest_block_number,
    );
    info!("traversal proposal event in L1 range: ({range_start}, {range_end})");
    filter_block_proposed_event(
        provider,
        chain_spec,
        EventFilterConditioin::Range((range_start, range_end)),
        l2_block_number,
        fork,
    )
    .await
}

pub async fn get_block_and_parent_data<BDP>(
    provider: &BDP,
    block_number: u64,
) -> RaikoResult<(RethBlock, alloy_rpc_types::Block)>
where
    BDP: BlockDataProvider,
{
    // Get the block and the parent block
    let blocks = provider
        .get_blocks(&[(block_number, true), (block_number - 1, false)])
        .await?;
    let mut blocks = blocks.iter();
    let Some(block) = blocks.next() else {
        return Err(RaikoError::Preflight(
            "No block data for the requested block".to_owned(),
        ));
    };
    let Some(parent_block) = blocks.next() else {
        return Err(RaikoError::Preflight(
            "No parent block data for the requested block".to_owned(),
        ));
    };

    info!(
        "Processing block {:?} with hash: {:?}",
        block.header.number, block.header.hash
    );
    debug!("block.parent_hash: {:?}", block.header.parent_hash);
    debug!("block gas used: {:?}", block.header.gas_used);
    debug!("block transactions: {:?}", block.transactions.len());

    // Convert the alloy block to a reth block
    let block = RethBlock::try_from(block.clone())
        .map_err(|e| RaikoError::Conversion(format!("Failed converting to reth block: {e}")))?;
    Ok((block, parent_block.clone()))
}

/// Get the timestamp of the grandparent block
pub async fn get_grandparent_timestamp<BDP: BlockDataProvider>(
    provider: &BDP,
    first_block_number: u64,
) -> RaikoResult<Option<u64>> {
    if first_block_number < 2 {
        return Ok(None);
    }

    let grandparent_block_number = first_block_number - 2;
    let grandparent_blocks = provider
        .get_blocks(&[(grandparent_block_number, false)])
        .await?;
    let grandparent_timestamp = grandparent_blocks
        .first()
        .map(|b| b.header.timestamp)
        .ok_or(RaikoError::Preflight(
            "No grandparent block for preflight".to_owned(),
        ))?;

    Ok(Some(grandparent_timestamp))
}

pub async fn get_batch_blocks_and_parent_data<BDP>(
    provider: &BDP,
    block_numbers: &[u64],
) -> RaikoResult<Vec<(RethBlock, alloy_rpc_types::Block)>>
where
    BDP: BlockDataProvider,
{
    let target_blocks = iter::once(block_numbers[0] - 1)
        .chain(block_numbers.iter().cloned())
        .enumerate()
        .map(|(i, block_number)| (block_number, i != 0))
        .collect::<Vec<(u64, bool)>>();
    // Get the block and the parent block
    let blocks = provider.get_blocks(&target_blocks).await?;
    assert!(blocks.len() == block_numbers.len() + 1);

    info!(
        "Processing {} blocks with (num, hash) from:({:?}, {:?}) to ({:?}, {:?})",
        block_numbers.len(),
        blocks.first().unwrap().header.number,
        blocks.first().unwrap().header.hash,
        blocks.last().unwrap().header.number,
        blocks.last().unwrap().header.hash,
    );

    let pairs = blocks
        .windows(2)
        .map(|window_blocks| {
            let parent_block = &window_blocks[0];
            let prove_block = RethBlock::try_from(window_blocks[1].clone())
                .map_err(|e| {
                    RaikoError::Conversion(format!("Failed converting to reth block: {e}"))
                })
                .unwrap();
            (prove_block, parent_block.clone())
        })
        .collect();

    Ok(pairs)
}

pub async fn get_headers<BDP>(provider: &BDP, (a, b): (u64, u64)) -> RaikoResult<(Header, Header)>
where
    BDP: BlockDataProvider,
{
    // Get the block and the parent block
    let blocks = provider.get_blocks(&[(a, true), (b, false)]).await?;
    let mut blocks = blocks.iter();
    let Some(a) = blocks.next() else {
        return Err(RaikoError::Preflight(
            "No block data for the requested block".to_owned(),
        ));
    };
    let Some(b) = blocks.next() else {
        return Err(RaikoError::Preflight(
            "No block data for the requested block".to_owned(),
        ));
    };

    // Convert the alloy block to a reth block
    Ok((a.header.clone(), b.header.clone()))
}

pub async fn get_max_anchor_headers<BDP>(
    provider: &BDP,
    anchor_tx_info_vec: Vec<(u64, B256)>,
    original_block_numbers: u64,
) -> RaikoResult<Vec<Header>>
where
    BDP: BlockDataProvider,
{
    assert!(!anchor_tx_info_vec.is_empty(), "anchor_tx_info is empty");
    let min_anchor_height = anchor_tx_info_vec[0].0;
    assert!(
        original_block_numbers - min_anchor_height <= ANCHOR_MAX_OFFSET as u64,
        "original_block_numbers - min_anchor_height > ANCHOR_MAX_OFFSET"
    );
    info!(
        "get max anchor L1 block headers in range: ({min_anchor_height}, {original_block_numbers})"
    );
    let all_init_block_numbers = (min_anchor_height..=original_block_numbers)
        .map(|block_number| (block_number, false))
        .collect::<Vec<_>>();
    // can filter out the block numbers that are already in the initial_db
    // but need to handle the block header db as well
    let initial_history_blocks = provider.get_blocks(&all_init_block_numbers).await?;

    // assert all anchor in this chain
    for anchor_tx_info in anchor_tx_info_vec {
        let block = initial_history_blocks
            .iter()
            .find(|block| block.header.number == anchor_tx_info.0);
        if block.is_none() {
            return Err(RaikoError::Preflight(format!(
                "Anchor block {} not found in the chain",
                anchor_tx_info.0
            )));
        }
    }

    Ok(initial_history_blocks
        .iter()
        .map(|block| block.header.clone())
        .collect())
}

/// Decodes extra data for Taiko chain containing base fee sharing percentage and bond proposal flag
///
/// # Arguments
/// * `extra_data` - The encoded extra data bytes
///
/// # Returns
/// A tuple containing (basefee_sharing_pctg, is_low_bond_proposal)
pub(crate) fn decode_extra_data(extra_data: &[u8]) -> (u8, bool) {
    if extra_data.len() < 2 {
        return (0, false);
    }

    // First byte: basefee sharing percentage
    let basefee_sharing_pctg = extra_data[0];

    // Second byte: is_low_bond_proposal in the lowest bit
    let is_low_bond_proposal = (extra_data[1] & 0x01) != 0;

    (basefee_sharing_pctg, is_low_bond_proposal)
}
