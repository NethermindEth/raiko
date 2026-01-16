use alloy_consensus::Transaction;
use alloy_primitives::{Log, B256};
use alloy_provider::{Provider, RootProvider};
use alloy_rpc_types::{Filter, Transaction as AlloyRpcTransaction};
use alloy_sol_types::SolEvent;
use anyhow::{anyhow, bail, Result};
use raiko_lib::{anchor::decode_anchor_ontake, consts::ChainSpec, input::ontake::CalldataTxList};

use crate::interfaces::RaikoError;

use super::filter_blockchain_event;

pub async fn get_calldata_txlist_event(
    provider: &RootProvider,
    chain_spec: ChainSpec,
    block_hash: B256,
    l2_block_number: u64,
) -> Result<(AlloyRpcTransaction, CalldataTxList)> {
    // Get the address that emitted the event
    let l1_address = chain_spec.get_fork_l1_contract_address(l2_block_number)?;

    let logs = filter_blockchain_event(provider, || {
        Filter::new()
            .address(l1_address)
            .at_block_hash(block_hash)
            .event_signature(CalldataTxList::SIGNATURE_HASH)
    })
    .await?;

    // Run over the logs returned to find the matching event for the specified L2 block number
    // (there can be multiple blocks proposed in the same block and even same tx)
    for log in logs {
        let Some(log_struct) = Log::new(
            log.address(),
            log.topics().to_vec(),
            log.data().data.clone(),
        ) else {
            bail!("Could not create log")
        };
        let event = CalldataTxList::decode_log(&log_struct)
            .map_err(|_| RaikoError::Anyhow(anyhow!("Could not decode log")))?;
        if event.blockId == raiko_lib::primitives::U256::from(l2_block_number) {
            let Some(log_tx_hash) = log.transaction_hash else {
                bail!("No transaction hash in the log")
            };
            let tx = provider
                .get_transaction_by_hash(log_tx_hash)
                .await
                .expect("couldn't query the propose tx")
                .expect("Could not find the propose tx");
            return Ok((tx, event.data));
        }
    }
    bail!("No BlockProposedV2 event found for block {l2_block_number}");
}

/// Get anchor block height and state root from Ontake anchor transaction
pub fn get_anchor_info(anchor_tx: &reth_primitives::TransactionSigned) -> Result<(u64, B256)> {
    let anchor_call = decode_anchor_ontake(anchor_tx.input())
        .map_err(|e| anyhow!("Failed to decode anchor tx: {e}"))?;
    Ok((anchor_call._anchorBlockId, anchor_call._anchorStateRoot))
}
