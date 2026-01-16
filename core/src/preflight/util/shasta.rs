use alloy_consensus::Transaction;
use alloy_primitives::B256;
use alloy_rpc_types::Header;
use anyhow::{anyhow, Result};
use raiko_lib::{
    anchor::decode_anchor_shasta,
    consts::ChainSpec,
    input::{
        shasta::ShastaEventData, BlobProofType, BlockProposedFork, InputDataSource,
        TaikoGuestBatchInput, TaikoProverData,
    },
};
use tracing::info;

use crate::{
    interfaces::{L1InclusionData, LimpModeData, RaikoResult},
    preflight::util::get_max_anchor_headers,
    provider::{rpc::RpcBlockDataProvider, BlockDataProvider},
};

use super::{filter_tx_blob_beacon_with_proof, get_batch_tx_data_with_proofs, get_headers};

/// Get anchor block height and state root from Shasta anchor transaction
pub fn get_anchor_info(anchor_tx: &reth_primitives::TransactionSigned) -> Result<(u64, B256)> {
    let anchor_call = decode_anchor_shasta(anchor_tx.input())
        .map_err(|e| anyhow!("Failed to decode anchor tx: {e}"))?;
    Ok((
        anchor_call._checkpoint.blockNumber.to(),
        anchor_call._checkpoint.stateRoot,
    ))
}

/// Prepare Shasta batch input
pub async fn prepare_batch_input(
    shasta_event_data: ShastaEventData,
    batch_id: u64,
    _l1_inclusion_block_number: u64,
    _anchor_block_height: u64,
    l1_inclusion_header: Header,
    l1_state_header: Header,
    l1_ancestor_headers: Vec<Header>,
    l1_chain_spec: &ChainSpec,
    _taiko_chain_spec: &ChainSpec,
    prover_data: TaikoProverData,
    blob_proof_type: &BlobProofType,
    _provider_l1: &RpcBlockDataProvider,
) -> RaikoResult<TaikoGuestBatchInput> {
    let mut data_sources = Vec::new();
    for derivation_source in shasta_event_data.proposal.sources.clone() {
        let blob_hashes = derivation_source.blobSlice.blobHashes;
        let is_forced_inclusion = derivation_source.isForcedInclusion;
        let l1_blob_timestamp = if is_forced_inclusion {
            // force inclusion block
            info!("force inclusion block, use derivation_source timestamp");
            derivation_source.blobSlice.timestamp.to()
        } else {
            l1_inclusion_header.timestamp
        };

        // according to protocol, calldata is mutex with blob
        let (tx_data_from_calldata, blob_tx_buffers_with_proofs) = if blob_hashes.is_empty() {
            unimplemented!("calldata txlist is not supported in shasta.");
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
        data_sources.push(InputDataSource {
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
        });
    }

    Ok(TaikoGuestBatchInput {
        batch_id,
        batch_proposed: BlockProposedFork::Shasta(shasta_event_data),
        l1_header: l1_state_header.try_into().unwrap(),
        l1_ancestor_headers: l1_ancestor_headers
            .into_iter()
            .map(|h| h.try_into().unwrap())
            .collect(),
        chain_spec: _taiko_chain_spec.clone(),
        prover_data,
        data_sources,
    })
}

/// Prepare Shasta batch input for limp mode
pub async fn prepare_limp_batch_input(
    shasta_event_data: ShastaEventData,
    batch_id: u64,
    limp_mode_data: LimpModeData,
    l1_state_header: Header,
    l1_ancestor_headers: Vec<Header>,
    taiko_chain_spec: &ChainSpec,
    prover_data: TaikoProverData,
    blob_proof_type: &BlobProofType,
) -> RaikoResult<TaikoGuestBatchInput> {
    let mut data_sources = Vec::new();
    for derivation_source in shasta_event_data.proposal.sources.clone() {
        let blob_hashes = derivation_source.blobSlice.blobHashes;
        let is_forced_inclusion = derivation_source.isForcedInclusion;

        let (tx_data_from_calldata, blob_tx_buffers_with_proofs) = if blob_hashes.is_empty() {
            unimplemented!("calldata txlist is not supported in shasta.");
        } else {
            let blob_data = limp_mode_data.get_blob_data();
            let mut tx_data = Vec::with_capacity(blob_hashes.len());

            let blobs: Vec<String> = blob_data.data.iter().map(|b| b.blob.clone()).collect();
            for hash in blob_hashes {
                let data =
                    filter_tx_blob_beacon_with_proof(hash, blobs.clone(), blob_proof_type).await?;
                tx_data.push(data);
            }

            (Vec::new(), tx_data)
        };

        data_sources.push(InputDataSource {
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
        });
    }

    Ok(TaikoGuestBatchInput {
        batch_id,
        batch_proposed: BlockProposedFork::Shasta(shasta_event_data),
        l1_header: l1_state_header.try_into().unwrap(),
        l1_ancestor_headers: l1_ancestor_headers
            .into_iter()
            .map(|h| h.try_into().unwrap())
            .collect(),
        chain_spec: taiko_chain_spec.clone(),
        prover_data,
        data_sources,
    })
}

pub async fn prepare_taiko_chain_batch_input(
    l1_chain_spec: &ChainSpec,
    taiko_chain_spec: &ChainSpec,
    l1_inclusion_data: L1InclusionData,
    batch_id: u64,
    prover_data: TaikoProverData,
    blob_proof_type: &BlobProofType,
    batch_anchor_tx_info: Vec<(u64, B256)>,
    shasta_event_data: raiko_lib::input::shasta::ShastaEventData,
) -> RaikoResult<TaikoGuestBatchInput> {
    let (anchor_block_height, _) = batch_anchor_tx_info[0];
    let provider_l1 = RpcBlockDataProvider::new(&l1_chain_spec.rpc).await?;

    match l1_inclusion_data {
        L1InclusionData::L1InclusionBlockNumber(l1_inclusion_block_number) => {
            assert!(
                l1_inclusion_block_number > 0,
                "l1_inclusion_block_number is 0"
            );
            // unlike pacaya that using anchor block as l1_state_header
            // shasta use parent block instead of anchor block because it connect anchor way through parent block
            let (l1_inclusion_header, l1_state_header) = get_headers(
                &provider_l1,
                (l1_inclusion_block_number, l1_inclusion_block_number - 1),
            )
            .await?;
            assert_eq!(l1_inclusion_header.parent_hash, l1_state_header.hash);

            let l1_ancestor_headers = get_max_anchor_headers(
                &provider_l1,
                batch_anchor_tx_info,
                l1_inclusion_block_number - 1,
            )
            .await?;

            prepare_batch_input(
                shasta_event_data,
                batch_id,
                l1_inclusion_block_number,
                anchor_block_height,
                l1_inclusion_header,
                l1_state_header,
                l1_ancestor_headers,
                l1_chain_spec,
                taiko_chain_spec,
                prover_data,
                blob_proof_type,
                &provider_l1,
            )
            .await
        }
        L1InclusionData::LimpModeData(limp_mode_data) => {
            let limp_proposed_event = limp_mode_data.get_limp_proposed_event();
            let origin_block_number = limp_proposed_event.origin_block_number;

            let l1_state_header = provider_l1
                .get_block((origin_block_number, false))
                .await?
                .header;

            let l1_ancestor_headers =
                get_max_anchor_headers(&provider_l1, batch_anchor_tx_info, origin_block_number)
                    .await?;

            prepare_limp_batch_input(
                shasta_event_data,
                batch_id,
                limp_mode_data,
                l1_state_header,
                l1_ancestor_headers,
                taiko_chain_spec,
                prover_data,
                blob_proof_type,
            )
            .await
        }
    }
}
