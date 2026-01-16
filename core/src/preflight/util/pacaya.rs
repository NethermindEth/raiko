use alloy_consensus::Transaction;
use alloy_primitives::B256;
use alloy_rpc_types::Header;
use anyhow::{anyhow, Result};
use raiko_lib::{
    anchor::decode_anchor_pacaya,
    consts::ChainSpec,
    input::{
        BlobProofType, BlockProposedFork, InputDataSource, TaikoGuestBatchInput, TaikoProverData,
    },
};
use tracing::info;

use crate::{interfaces::RaikoResult, provider::rpc::RpcBlockDataProvider};

use super::{get_batch_tx_data_with_proofs, get_headers};

/// Get anchor block height and state root from Pacaya anchor transaction
pub fn get_anchor_info(anchor_tx: &reth_primitives::TransactionSigned) -> Result<(u64, B256)> {
    let anchor_call = decode_anchor_pacaya(anchor_tx.input())
        .map_err(|e| anyhow!("Failed to decode anchor tx: {e}"))?;
    Ok((anchor_call._anchorBlockId, anchor_call._anchorStateRoot))
}

/// Prepare Pacaya batch input
pub async fn prepare_batch_input(
    batch_proposed: raiko_lib::input::pacaya::BatchProposed,
    batch_id: u64,
    l1_inclusion_block_number: u64,
    anchor_block_height: u64,
    l1_inclusion_header: Header,
    l1_state_header: Header,
    l1_chain_spec: &ChainSpec,
    taiko_chain_spec: &ChainSpec,
    prover_data: TaikoProverData,
    blob_proof_type: &BlobProofType,
    provider_l1: &RpcBlockDataProvider,
) -> RaikoResult<TaikoGuestBatchInput> {
    let batch_info = &batch_proposed.info;
    let blob_hashes = batch_info.blobHashes.clone();
    let force_inclusion_block_number = batch_info.blobCreatedIn;
    let is_forced_inclusion = force_inclusion_block_number != 0
        && force_inclusion_block_number != l1_inclusion_block_number;
    let l1_blob_timestamp = if is_forced_inclusion {
        // force inclusion block
        info!(
            "force inclusion block number: {force_inclusion_block_number}, use its header timestamp"
        );
        let (force_inclusion_header, _) = get_headers(
            provider_l1,
            (force_inclusion_block_number, anchor_block_height),
        )
        .await?;
        force_inclusion_header.timestamp
    } else {
        l1_inclusion_header.timestamp
    };

    // according to protocol, calldata is mutex with blob
    let (tx_data_from_calldata, blob_tx_buffers_with_proofs) = if blob_hashes.is_empty() {
        let tx_list = &batch_proposed.txList;
        (tx_list.to_vec(), Vec::new())
    } else {
        let blob_tx_buffers = get_batch_tx_data_with_proofs(
            blob_hashes,
            l1_blob_timestamp,
            l1_chain_spec,
            blob_proof_type,
        )
        .await?;
        (Vec::new(), blob_tx_buffers)
    };

    Ok(TaikoGuestBatchInput {
        batch_id,
        batch_proposed: BlockProposedFork::Pacaya(batch_proposed),
        l1_header: l1_state_header.try_into().unwrap(),
        l1_ancestor_headers: Vec::new(),
        chain_spec: taiko_chain_spec.clone(),
        prover_data,
        data_sources: vec![InputDataSource {
            tx_data_from_calldata,
            tx_data_from_blob: blob_tx_buffers_with_proofs
                .iter()
                .map(|(data, _, _)| data.clone())
                .collect(),
            blob_commitments: Some(
                blob_tx_buffers_with_proofs
                    .iter()
                    .filter_map(|(_, commitment, _)| commitment.clone())
                    .collect(),
            ),
            blob_proofs: Some(
                blob_tx_buffers_with_proofs
                    .iter()
                    .filter_map(|(_, _, proof)| proof.clone())
                    .collect(),
            ),
            blob_proof_type: blob_proof_type.clone(),
            is_forced_inclusion,
        }],
    })
}

pub async fn prepare_taiko_chain_batch_input(
    l1_chain_spec: &ChainSpec,
    taiko_chain_spec: &ChainSpec,
    l1_inclusion_block_number: u64,
    batch_id: u64,
    prover_data: TaikoProverData,
    blob_proof_type: &BlobProofType,
    batch_anchor_tx_info: Vec<(u64, B256)>,
    batch_proposed: raiko_lib::input::pacaya::BatchProposed,
) -> RaikoResult<TaikoGuestBatchInput> {
    let (anchor_block_height, anchor_state_root) = batch_anchor_tx_info[0];
    let provider_l1 = RpcBlockDataProvider::new(&l1_chain_spec.rpc).await?;

    let (l1_inclusion_header, l1_state_header) = get_headers(
        &provider_l1,
        (l1_inclusion_block_number, anchor_block_height),
    )
    .await?;
    assert_eq!(anchor_state_root, l1_state_header.state_root);

    prepare_batch_input(
        batch_proposed,
        batch_id,
        l1_inclusion_block_number,
        anchor_block_height,
        l1_inclusion_header,
        l1_state_header,
        l1_chain_spec,
        taiko_chain_spec,
        prover_data,
        blob_proof_type,
        &provider_l1,
    )
    .await
}
