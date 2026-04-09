use crate::{
    interfaces::{RaikoError, RaikoResult},
    provider::BlockDataProvider,
};
use alethia_reth_primitives::TaikoTxEnvelope;
use futures::future::join_all;
use raiko_lib::{
    consts::ChainSpec,
    input::{
        BlobProofType, BlockProposedFork, GuestBatchInput, GuestInput, TaikoGuestInput,
        TaikoProverData,
    },
    proof_type::ProofType,
    utils::txs::generate_transactions_for_batch_blocks,
};
use tracing::{debug, info};

use util::{
    get_batch_blocks_and_parent_data, get_block_and_parent_data, prepare_taiko_chain_batch_input,
    prepare_taiko_chain_input,
};

pub use util::{
    parse_l1_batch_proposal_tx_for_pacaya_fork, parse_l1_batch_proposal_tx_for_shasta_fork,
};

mod util;

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

pub async fn preflight<BDP: BlockDataProvider, L1BDP: BlockDataProvider>(
    l2_provider: BDP,
    l1_provider: &L1BDP,
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
    debug!("preflight: start for block {block_number}");

    let (block, parent_block) = get_block_and_parent_data(&l2_provider, block_number).await?;
    debug!("preflight: L2 block + parent fetched");

    let taiko_guest_input = if taiko_chain_spec.is_taiko() {
        prepare_taiko_chain_input(
            &l1_chain_spec,
            &taiko_chain_spec,
            block_number,
            (l1_inclusion_block_number != 0).then_some(l1_inclusion_block_number),
            &block,
            prover_data,
            &blob_proof_type,
            l1_provider,
        )
        .await?
    } else {
        TaikoGuestInput::try_from(block.body.transactions.clone())
            .map_err(|e| RaikoError::Conversion(e.0))?
    };
    debug!("preflight: taiko guest input done");

    let parent_header: reth_primitives::Header = parent_block.header.inner.clone();

    let input = GuestInput {
        block: block.clone(),
        parent_header,
        chain_spec: taiko_chain_spec.clone(),
        taiko: taiko_guest_input,
        ..Default::default()
    };

    if proof_type == ProofType::Tdx {
        debug!("preflight: skipping re-execution since TDX proof");
        return Ok(input);
    }

    let witness = l2_provider
        .execution_witness(block_number)
        .await
        .ok_or_else(|| {
            RaikoError::Preflight("execution witness not supported by provider".to_owned())
        })?
        .map_err(|e| RaikoError::Preflight(format!("execution witness failed: {e}")))?;
    debug!("preflight: execution witness fetched");

    let (parent_state_trie, parent_storage, contracts, ancestor_headers) =
        raiko_lib::primitives::mpt::witness_to_tries(
            input.parent_header.state_root,
            witness.state,
            witness.keys,
            witness.codes,
            witness.headers,
        )?;
    debug!("preflight: witness_to_tries done");

    Ok(GuestInput {
        parent_state_trie,
        parent_storage,
        contracts,
        ancestor_headers,
        ..input
    })
}

pub async fn batch_preflight<BDP: BlockDataProvider, L1BDP: BlockDataProvider>(
    l2_provider: BDP,
    l1_provider: &L1BDP,
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
    debug!("batch_preflight: start for {} blocks", block_numbers.len());

    let all_block_parent_pairs =
        get_batch_blocks_and_parent_data(&l2_provider, &block_numbers).await?;
    debug!("batch_preflight: L2 blocks fetched");

    let (l2_grandparent_header, block_parent_pairs) = if block_numbers[0] == 1 {
        (None, all_block_parent_pairs)
    } else {
        debug!("all_block_parent_pairs: {:?}", all_block_parent_pairs);
        (
            all_block_parent_pairs
                .first()
                .map(|(_, parent_block)| parent_block.header.clone().try_into().unwrap()),
            all_block_parent_pairs.into_iter().skip(1).collect(),
        )
    };

    // Extract grandparent timestamp before l2_grandparent_header is moved below.
    // Block (first_block - 2) was already fetched by get_batch_blocks_and_parent_data,
    // so no extra RPC call is needed.
    let mut grandparent_timestamp: Option<u64> = l2_grandparent_header
        .as_ref()
        .map(|h: &reth_primitives::Header| h.timestamp);

    info!(
        "batch preflight {} l2_block_numbers: {:?} to {:?}.",
        block_numbers.len(),
        block_numbers.first(),
        block_numbers.last(),
    );
    let (prove_blocks, parent_blocks): (Vec<_>, Vec<_>) = block_parent_pairs.into_iter().unzip();

    if prove_blocks.is_empty() {
        return Err(RaikoError::Preflight(
            "No blocks to prove in batch".to_owned(),
        ));
    }

    let taiko_guest_batch_input = if taiko_chain_spec.is_taiko() {
        prepare_taiko_chain_batch_input(
            &l1_chain_spec,
            &taiko_chain_spec,
            l1_inclusion_block_number,
            batch_id,
            &prove_blocks,
            prover_data,
            &blob_proof_type,
            cached_event_data,
            l2_grandparent_header,
            l1_provider,
        )
        .await?
    } else {
        return Err(RaikoError::Preflight(
            "Batch preflight is only used for Taiko chains".to_owned(),
        ));
    };
    debug!("batch_preflight: L1 taiko input done");

    let minimal_inputs: Vec<GuestInput> = prove_blocks
        .into_iter()
        .zip(parent_blocks)
        .map(|(block, parent_block)| GuestInput {
            block,
            parent_header: parent_block.header.try_into().unwrap(),
            chain_spec: taiko_chain_spec.clone(),
            ..Default::default()
        })
        .collect();

    let guest_batch_input = GuestBatchInput {
        inputs: minimal_inputs,
        taiko: taiko_guest_batch_input,
    };

    let pool_txs_list: Vec<(Vec<TaikoTxEnvelope>, bool)> =
        generate_transactions_for_batch_blocks(&guest_batch_input);
    debug!("batch_preflight: tx distribution done");

    assert_eq!(guest_batch_input.inputs.len(), pool_txs_list.len());

    let GuestBatchInput {
        inputs: minimal_inputs,
        taiko: taiko_guest_batch_input,
    } = guest_batch_input;

    let mut base_inputs: Vec<GuestInput> = Vec::with_capacity(minimal_inputs.len());
    for (input, (_pool_txs, is_force_inclusion)) in
        minimal_inputs.into_iter().zip(pool_txs_list.iter())
    {
        let anchor_tx = input.block.body.transactions.first().unwrap().clone();
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

        grandparent_timestamp = Some(input.parent_header.timestamp);

        base_inputs.push(GuestInput {
            taiko: taiko_input,
            ..input
        });
    }

    if proof_type == ProofType::Tdx {
        debug!("batch_preflight: skipping re-execution since TDX proof");
        return Ok(GuestBatchInput {
            inputs: base_inputs,
            taiko: taiko_guest_batch_input,
        });
    }

    // Fetch all witnesses concurrently
    let witness_futures: Vec<_> = base_inputs
        .iter()
        .map(|input| {
            let block_number = input.block.header.number;
            let l2_provider = &l2_provider;
            async move {
                l2_provider
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
    debug!("batch_preflight: all {} witnesses fetched", witnesses.len());

    // Apply witness data to each input
    let mut final_inputs: Vec<GuestInput> = Vec::with_capacity(base_inputs.len());
    for (input, witness_result) in base_inputs.into_iter().zip(witnesses) {
        let witness = witness_result?;
        let block_number = input.block.header.number;
        debug!("batch_preflight: block {block_number} applying witness");

        let (parent_state_trie, parent_storage, contracts, ancestor_headers) =
            raiko_lib::primitives::mpt::witness_to_tries(
                input.parent_header.state_root,
                witness.state,
                witness.keys,
                witness.codes,
                witness.headers,
            )?;
        debug!("batch_preflight: block {block_number} witness_to_tries done");

        final_inputs.push(GuestInput {
            parent_state_trie,
            parent_storage,
            contracts,
            ancestor_headers,
            ..input
        });
    }

    debug!("batch_preflight: all done");
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
