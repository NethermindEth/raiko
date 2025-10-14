use core::mem;
use std::sync::Arc;
use std::sync::LazyLock;

use crate::primitives::keccak::keccak;
use crate::primitives::mpt::StateAccount;
use crate::utils::{generate_transactions, generate_transactions_for_batch_blocks};
use crate::{
    consts::{ChainSpec, MAX_BLOCK_HASH_AGE},
    guest_mem_forget,
    input::{GuestBatchInput, GuestInput, L1StorageProof},
    mem_db::{AccountState, DbAccount, MemDb},
    CycleTracker,
};
use alloy_primitives::Sealable;
use alloy_rlp::Decodable;
use alloy_trie::{proof::verify_proof, Nibbles};
use anyhow::{bail, ensure, Context, Result};
use reth_chainspec::{ChainHardforks, EthChainSpec, EthereumHardfork, ForkCondition, Hardforks};
use reth_consensus::{Consensus, HeaderValidator};
use reth_ethereum_consensus::validate_block_post_execution;
use reth_evm::execute::{
    BlockExecutionOutput, BlockExecutorProvider, BlockValidationError, ProviderError,
};
use reth_primitives::revm_primitives::db::{Database, DatabaseCommit};
use reth_primitives::revm_primitives::{
    Account, AccountInfo, AccountStatus, Bytecode, Bytes, EvmStorageSlot, HashMap, SpecId,
    KECCAK_EMPTY,
};
use reth_primitives::{
    Address, Block, BlockExt, BlockWithSenders, Header, TransactionSigned, B256, U256,
};
use reth_taiko_chainspec::spec::{TAIKO_A7, TAIKO_DEV, TAIKO_MAINNET};
use reth_taiko_chainspec::TaikoChainSpec;
use reth_taiko_consensus::{TaikoData, TaikoSimpleBeaconConsensus};
use reth_taiko_evm::TaikoExecutorProviderBuilder;
use reth_taiko_forks::TaikoHardfork;
use revm_precompile::l1sload::set_l1_storage_value;

use tracing::{debug, error, info};

/// Surge dev list of hardforks.
pub static SURGE_DEV_HARDFORKS: LazyLock<reth_chainspec::ChainHardforks> = LazyLock::new(|| {
    ChainHardforks::new(vec![
        (EthereumHardfork::Frontier.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Homestead.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Dao.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Tangerine.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::SpuriousDragon.boxed(),
            ForkCondition::Block(0),
        ),
        (EthereumHardfork::Byzantium.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::Constantinople.boxed(),
            ForkCondition::Block(0),
        ),
        (
            EthereumHardfork::Petersburg.boxed(),
            ForkCondition::Block(0),
        ),
        (EthereumHardfork::Istanbul.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Berlin.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::London.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::Paris.boxed(),
            ForkCondition::TTD {
                fork_block: None,
                total_difficulty: U256::from(0),
            },
        ),
        (
            EthereumHardfork::Shanghai.boxed(),
            ForkCondition::Timestamp(0),
        ),
        (TaikoHardfork::Hekla.boxed(), ForkCondition::Block(0)),
        (
            TaikoHardfork::Ontake.boxed(),
            ForkCondition::Block(
                std::env::var("SURGE_DEV_ONTAKE_HEIGHT").map_or(1, |h| h.parse().unwrap_or(1)),
            ),
        ),
        (TaikoHardfork::Pacaya.boxed(), ForkCondition::Block(1)),
    ])
});

pub static SURGE_TEST_HARDFORKS: LazyLock<reth_chainspec::ChainHardforks> = LazyLock::new(|| {
    ChainHardforks::new(vec![
        (EthereumHardfork::Frontier.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Homestead.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Dao.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Tangerine.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::SpuriousDragon.boxed(),
            ForkCondition::Block(0),
        ),
        (EthereumHardfork::Byzantium.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::Constantinople.boxed(),
            ForkCondition::Block(0),
        ),
        (
            EthereumHardfork::Petersburg.boxed(),
            ForkCondition::Block(0),
        ),
        (EthereumHardfork::Istanbul.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Berlin.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::London.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::Paris.boxed(),
            ForkCondition::TTD {
                fork_block: None,
                total_difficulty: U256::from(0),
            },
        ),
        (
            EthereumHardfork::Shanghai.boxed(),
            ForkCondition::Timestamp(0),
        ),
        (TaikoHardfork::Hekla.boxed(), ForkCondition::Block(0)),
        (
            TaikoHardfork::Ontake.boxed(),
            ForkCondition::Block(
                std::env::var("SURGE_TESTNET_ONTAKE_HEIGHT").map_or(1, |h| h.parse().unwrap_or(1)),
            ),
        ),
        (TaikoHardfork::Pacaya.boxed(), ForkCondition::Block(1)),
    ])
});

pub static SURGE_STAGE_HARDFORKS: LazyLock<reth_chainspec::ChainHardforks> = LazyLock::new(|| {
    ChainHardforks::new(vec![
        (EthereumHardfork::Frontier.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Homestead.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Dao.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Tangerine.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::SpuriousDragon.boxed(),
            ForkCondition::Block(0),
        ),
        (EthereumHardfork::Byzantium.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::Constantinople.boxed(),
            ForkCondition::Block(0),
        ),
        (
            EthereumHardfork::Petersburg.boxed(),
            ForkCondition::Block(0),
        ),
        (EthereumHardfork::Istanbul.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::Berlin.boxed(), ForkCondition::Block(0)),
        (EthereumHardfork::London.boxed(), ForkCondition::Block(0)),
        (
            EthereumHardfork::Paris.boxed(),
            ForkCondition::TTD {
                fork_block: None,
                total_difficulty: U256::from(0),
            },
        ),
        (
            EthereumHardfork::Shanghai.boxed(),
            ForkCondition::Timestamp(0),
        ),
        (TaikoHardfork::Hekla.boxed(), ForkCondition::Block(0)),
        (
            TaikoHardfork::Ontake.boxed(),
            ForkCondition::Block(
                std::env::var("SURGE_STAGING_ONTAKE_HEIGHT").map_or(1, |h| h.parse().unwrap_or(1)),
            ),
        ),
        (TaikoHardfork::Pacaya.boxed(), ForkCondition::Block(1)),
    ])
});

pub static SURGE_DEV: LazyLock<Arc<TaikoChainSpec>> = LazyLock::new(|| {
    let hardforks = SURGE_DEV_HARDFORKS.clone();
    TaikoChainSpec {
        inner: reth_chainspec::ChainSpec {
            chain: 763374.into(), // TODO: make this dynamic based on the chain spec
            paris_block_and_final_difficulty: None,
            hardforks,
            deposit_contract: None,
            ..Default::default()
        },
    }
    .into()
});

pub static SURGE_STAGE: LazyLock<Arc<TaikoChainSpec>> = LazyLock::new(|| {
    let hardforks = SURGE_STAGE_HARDFORKS.clone();
    TaikoChainSpec {
        inner: reth_chainspec::ChainSpec {
            chain: 763373.into(), // TODO: make this dynamic based on the chain spec
            paris_block_and_final_difficulty: None,
            hardforks,
            deposit_contract: None,
            ..Default::default()
        },
    }
    .into()
});

pub static SURGE_TEST: LazyLock<Arc<TaikoChainSpec>> = LazyLock::new(|| {
    let hardforks = SURGE_TEST_HARDFORKS.clone();
    TaikoChainSpec {
        inner: reth_chainspec::ChainSpec {
            chain: 763375.into(), // TODO: make this dynamic based on the chain spec
            paris_block_and_final_difficulty: None,
            hardforks,
            deposit_contract: None,
            ..Default::default()
        },
    }
    .into()
});

pub static SURGE_MAINNET: LazyLock<Arc<TaikoChainSpec>> = LazyLock::new(|| {
    let hardforks = SURGE_STAGE_HARDFORKS.clone();
    TaikoChainSpec {
        inner: reth_chainspec::ChainSpec {
            chain: 763374.into(), // TODO: make this dynamic based on the chain spec
            paris_block_and_final_difficulty: None,
            hardforks,
            deposit_contract: None,
            ..Default::default()
        },
    }
    .into()
});

/// Verify and populate L1SLOAD cache with storage values before EVM execution
/// This must be called before any EVM execution to ensure L1SLOAD precompile has access to L1 data
fn verify_and_populate_l1sload_cache(
    l1_storage_proofs: &[L1StorageProof],
    anchor_state_root: B256,
) -> Result<()> {
    for (i, proof) in l1_storage_proofs.iter().enumerate() {
        // Verify L1 storage proof against anchor state root
        if let Err(e) = verify_l1_proof(proof, anchor_state_root) {
            bail!(
                "L1SLOAD proof verification failed for proof #{} (contract={:?}, key={:?}, block={:?}): {}",
                i,
                proof.contract_address,
                proof.storage_key,
                proof.block_number,
                e
            );
        }

        // Populate REVM L1SLOAD cache with verified value
        set_l1_storage_value(
            proof.contract_address,
            proof.storage_key,
            proof.block_number,
            proof.value,
        );

        info!(
            "Verified and cached L1SLOAD: contract={:?}, key={:?}, block={:?}, value={:?}",
            proof.contract_address, proof.storage_key, proof.block_number, proof.value
        );
    }

    info!(
        "Successfully verified and populated {} L1SLOAD storage proofs",
        l1_storage_proofs.len()
    );
    Ok(())
}

/// Verify L1 storage and account proof against anchor state root using MPT proof verification
/// For non-existent accounts/storage should return zero, given that the provided proofs are empty.
fn verify_l1_proof(proof: &L1StorageProof, anchor_state_root: B256) -> Result<()> {
    // Get and verify account data
    let account_key = B256::from(keccak(proof.contract_address.as_slice()));
    let account_rlp = get_and_verify_value(account_key, anchor_state_root, &proof.account_proof)?;

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

    info!(
        "L1 storage proof verified for contract {:?}, value={:?}",
        proof.contract_address, proof.value
    );
    Ok(())
}

/// Get value and verify proof
fn get_and_verify_value(key_hash: B256, root: B256, proof: &[Bytes]) -> Result<Vec<u8>> {
    // Handle empty proof array (proves non-existence at the root level)
    if proof.is_empty() {
        // For non-existent keys, verify against the root
        let nibbles = Nibbles::unpack(&key_hash);
        let proof_refs: Vec<&Bytes> = Vec::new();
        verify_proof(root, nibbles, None, proof_refs)?;
        return Ok(Vec::new());
    }

    let nibbles = Nibbles::unpack(&key_hash);
    let proof_refs: Vec<&Bytes> = proof.iter().collect();

    // Try with None first (empty/non-existent)
    if verify_proof(root, nibbles.clone(), None, proof_refs.clone()).is_ok() {
        return Ok(Vec::new());
    }

    // Extract and verify actual value
    let value = get_leaf_value(proof)?;
    let value_option = if value.is_empty() {
        None
    } else {
        Some(value.clone())
    };
    verify_proof(root, nibbles, value_option, proof_refs)?;

    Ok(value)
}

/// Extract value from leaf node
fn get_leaf_value(proof: &[Bytes]) -> Result<Vec<u8>> {
    let last_node = proof.last().ok_or_else(|| anyhow::anyhow!("Empty proof"))?;
    let mut rlp = last_node.as_ref();
    let decoded: Vec<Vec<u8>> = Vec::decode(&mut rlp).with_context(|| {
        format!(
            "Failed to decode last proof node as Vec<Vec<u8>>, raw bytes: 0x{}, proof has {} nodes",
            hex::encode(last_node),
            proof.len()
        )
    })?;

    // Return the value part of a 2-element leaf node, or empty for other cases
    if decoded.len() == 2 {
        info!(
            "Extracted leaf value: {} bytes from {}-element node",
            decoded[1].len(),
            decoded.len()
        );
        Ok(decoded[1].clone())
    } else {
        info!(
            "Last node is not a 2-element leaf (has {} elements), treating as non-existent",
            decoded.len()
        );
        Ok(Vec::new())
    }
}

/// Extract storage root from account RLP
fn get_storage_root(account_rlp: &[u8]) -> Result<B256> {
    let mut rlp = account_rlp;
    let account: Vec<Vec<u8>> = Vec::decode(&mut rlp).with_context(|| {
        format!(
            "Failed to decode account RLP, raw bytes: {:?}",
            hex::encode(account_rlp)
        )
    })?;
    if account.len() < 3 {
        bail!(
            "Invalid account format: expected at least 3 fields, got {}, raw bytes: {:?}",
            account.len(),
            hex::encode(account_rlp)
        );
    }
    Ok(B256::from_slice(&account[2]))
}

pub fn calculate_block_header(input: &GuestInput) -> Header {
    let cycle_tracker = CycleTracker::start("initialize_database");
    let db = create_mem_db(&mut input.clone()).unwrap();
    cycle_tracker.end();

    if !input.l1_storage_proofs.is_empty() {
        let anchor_state_root = input.taiko.l1_header.state_root;
        verify_and_populate_l1sload_cache(&input.l1_storage_proofs, anchor_state_root)
            .expect("Failed to verify and populate L1SLOAD cache for block");
    }

    let mut builder = RethBlockBuilder::new(input, db);
    let pool_tx = generate_transactions(
        &input.chain_spec,
        &input.taiko.block_proposed,
        &input.taiko.tx_data,
        &input.taiko.anchor_tx,
    );

    let cycle_tracker = CycleTracker::start("execute_transactions");
    builder
        .execute_transactions(pool_tx, false)
        .expect("execute");
    cycle_tracker.end();

    let cycle_tracker = CycleTracker::start("finalize");
    let header = builder.finalize().expect("execute");
    cycle_tracker.end();

    header
}

pub fn calculate_batch_blocks_final_header(input: &GuestBatchInput) -> Vec<Block> {
    let pool_txs_list = generate_transactions_for_batch_blocks(&input.taiko);
    let mut final_blocks = Vec::new();
    for (i, pool_txs) in pool_txs_list.iter().enumerate() {
        if !input.inputs[i].l1_storage_proofs.is_empty() {
            let anchor_state_root = input.inputs[i].taiko.l1_header.state_root;
            verify_and_populate_l1sload_cache(
                &input.inputs[i].l1_storage_proofs,
                anchor_state_root,
            )
            .expect(&format!(
                "Failed to verify and populate L1SLOAD cache for batch block #{}",
                i
            ));
        }

        let mut builder = RethBlockBuilder::new(
            &input.inputs[i],
            create_mem_db(&mut input.inputs[i].clone()).unwrap(),
        );

        let mut execute_tx = vec![input.inputs[i].taiko.anchor_tx.clone().unwrap()];
        execute_tx.extend_from_slice(&pool_txs);
        builder
            .execute_transactions(execute_tx.clone(), false)
            .expect("execute");
        final_blocks.push(
            builder
                .finalize_block()
                .expect("execute single batched block"),
        );
    }
    validate_final_batch_blocks(input, &final_blocks);
    final_blocks
}

// to check the linkages between the blocks
// 1. connect parent hash & state root
// 2. block number should be in sequence
fn validate_final_batch_blocks(input: &GuestBatchInput, final_blocks: &[Block]) {
    input
        .inputs
        .iter()
        .zip(final_blocks.iter())
        .collect::<Vec<_>>()
        .windows(2)
        .for_each(|window| {
            let (_parent_input, parent_block) = &window[0];
            let (current_input, current_block) = &window[1];
            let calculated_parent_hash = parent_block.header.hash_slow();
            assert!(
                calculated_parent_hash == current_block.header.parent_hash,
                "Parent hash mismatch, expected: {}, got: {}",
                calculated_parent_hash,
                current_block.header.parent_hash
            );
            assert!(
                parent_block.header.number + 1 == current_block.header.number,
                "Block number mismatch, expected: {}, got: {}",
                parent_block.header.number + 1,
                current_block.header.number
            );
            assert!(
                parent_block.header.state_root == current_input.parent_header.state_root,
                "Parent hash mismatch, expected: {}, got: {}",
                parent_block.header.hash_slow(),
                current_block.header.parent_hash
            );
            // state root is checked in finalize(), skip here
            // assert!(current_block.state_root == current_input.block.state_root)
        });
}

/// Optimistic database
#[allow(async_fn_in_trait)]
pub trait OptimisticDatabase {
    /// Handle post execution work
    async fn fetch_data(&mut self) -> bool;

    /// If the current database is optimistic
    fn is_optimistic(&self) -> bool;
}
/// A generic builder for building a block.
#[derive(Clone, Debug)]
pub struct RethBlockBuilder<DB> {
    pub chain_spec: ChainSpec,
    pub input: GuestInput,
    pub db: Option<DB>,
}

impl<DB: Database<Error = ProviderError> + DatabaseCommit + OptimisticDatabase>
    RethBlockBuilder<DB>
{
    /// Creates a new block builder.
    pub fn new(input: &GuestInput, db: DB) -> RethBlockBuilder<DB> {
        RethBlockBuilder {
            chain_spec: input.chain_spec.clone(),
            db: Some(db),
            input: input.clone(),
        }
    }

    /// Executes all input transactions.
    pub fn execute_transactions(
        &mut self,
        pool_txs: Vec<TransactionSigned>,
        optimistic: bool,
    ) -> Result<()> {
        info!("execute_transactions: start");
        // Get the chain spec
        let chain_spec = &self.input.chain_spec;
        let total_difficulty = U256::ZERO;
        let reth_chain_spec = match chain_spec.name.as_str() {
            "taiko_a7" => TAIKO_A7.clone(),
            "taiko_mainnet" => TAIKO_MAINNET.clone(),
            "taiko_dev" => TAIKO_DEV.clone(),
            "surge_dev" => SURGE_DEV.clone(),
            "surge_test" => SURGE_TEST.clone(),
            "surge_stage" => SURGE_STAGE.clone(),
            "surge_mainnet" => SURGE_MAINNET.clone(),
            _ => unimplemented!(),
        };

        info!("execute_transactions: reth_chain_spec done");

        if reth_chain_spec.is_taiko() {
            let block_num = self.input.taiko.block_proposed.block_number();
            let block_timestamp = 0u64; // self.input.taiko.block_proposed.block_timestamp();

            let taiko_fork = self
                .input
                .chain_spec
                .spec_id(block_num, block_timestamp)
                .unwrap();

            match taiko_fork {
                SpecId::HEKLA => {
                    assert!(
                        reth_chain_spec
                            .fork(TaikoHardfork::Hekla)
                            .active_at_block(block_num),
                        "evm fork HEKLA is not active, please update the chain spec"
                    );
                }
                SpecId::ONTAKE => {
                    assert!(
                        reth_chain_spec
                            .fork(TaikoHardfork::Ontake)
                            .active_at_block(block_num),
                        "evm fork ONTAKE is not active, please update the chain spec"
                    );
                }
                SpecId::PACAYA => {
                    assert!(
                        reth_chain_spec
                            .fork(TaikoHardfork::Pacaya)
                            .active_at_block(block_num),
                        "evm fork PACAYA is not active, please update the chain spec"
                    );
                }
                _ => unimplemented!(),
            }
            info!("execute_transactions: is_taiko done");
        }

        // Generate the transactions from the tx list
        let mut block = self.input.block.clone();
        block.body.transactions = pool_txs;
        // Recover senders
        let mut block = block
            .with_recovered_senders()
            .ok_or(BlockValidationError::SenderRecoveryError)?;

        let base_fee_config = self.input.taiko.block_proposed.base_fee_config();
        let gas_limit = self.input.taiko.block_proposed.gas_limit_with_anchor();

        let taiko_chain_spec = Arc::new(TaikoChainSpec::from((*reth_chain_spec).clone()));

        let executor = TaikoExecutorProviderBuilder::new(
            taiko_chain_spec.clone(),
            TaikoData {
                l1_header: self.input.taiko.l1_header.clone(),
                parent_header: self.input.parent_header.clone(),
                l2_contract: self.input.chain_spec.l2_contract.unwrap_or_default(),
                base_fee_config,
                gas_limit,
            },
        )
        .with_optimistic(optimistic)
        .build()
        .executor(self.db.take().unwrap());

        let (
            BlockExecutionOutput {
                state,
                receipts,
                requests,
                gas_used: _,
                skipped_list,
            },
            full_state,
        ) = executor
            .execute_and_get_state((&block, total_difficulty).into())
            .map_err(|e| {
                error!("Error executing block: {e:?}");
                e
            })?;

        info!("execute_transactions: execute done");
        // Filter out the valid transactions so that the header checks only take these into account
        block.body.transactions = block
            .body
            .transactions
            .iter()
            .enumerate()
            .filter(|(i, _)| !skipped_list.contains(i))
            .map(|(_, tx)| tx.clone())
            .collect();
        info!("execute_transactions: valid_transaction_indices done");
        // Header validation
        // TODO: Use TaikoConsensus for this?
        let block = block.seal_slow();
        if !optimistic {
            let consensus = TaikoSimpleBeaconConsensus::new(reth_chain_spec.clone());
            // Validates extra data
            consensus.validate_header_with_total_difficulty(&block.header, total_difficulty)?;
            info!("execute_transactions: validate_header_with_total_difficulty done");
            // Validates if some values are set that should not be set for the current HF
            consensus.validate_header(&block.header)?;
            info!("execute_transactions: validate_header done");
            // Validates parent block hash, block number and timestamp
            let parent = self.input.parent_header.clone().seal_slow();
            consensus.validate_header_against_parent(&block.header, &parent.into())?;
            info!("execute_transactions: validate_header_against_parent done");
            // Validates ommers hash, transaction root, withdrawals root
            consensus.validate_block_pre_execution(&block)?;
            info!("execute_transactions: validate_block_pre_execution done");
            // Validates the gas used, the receipts root and the logs bloom
            validate_block_post_execution(
                &BlockWithSenders {
                    block: block.block.unseal(),
                    senders: block.senders,
                },
                &reth_chain_spec.clone(),
                &receipts,
                &requests,
            )?;
            info!("execute_transactions: validate_block_post_execution done");
        }

        // Apply DB changes
        self.db = Some(full_state.database);
        info!("execute_transactions: changes start");
        let changes: HashMap<Address, Account> = state
            .state
            .into_iter()
            .map(|(address, bundle_account)| {
                let mut account = Account {
                    info: bundle_account.account_info().unwrap_or_default(),
                    storage: bundle_account
                        .storage
                        .into_iter()
                        .map(|(k, v)| {
                            (
                                k,
                                EvmStorageSlot {
                                    original_value: v.original_value(),
                                    present_value: v.present_value(),
                                    // is_cold used in EIP-2929 for optimizing gas costs for slot accesses, we don't need this in proving
                                    is_cold: false,
                                },
                            )
                        })
                        .collect(),
                    status: AccountStatus::default(),
                };
                account.mark_touch();
                if bundle_account.info.is_none() {
                    account.mark_selfdestruct();
                }
                if bundle_account.original_info.is_none() {
                    account.mark_created();
                }
                (address, account)
            })
            .collect();
        info!("execute_transactions: changes done");
        self.db.as_mut().unwrap().commit(changes);
        info!("execute_transactions: commit done");
        Ok(())
    }
}

impl RethBlockBuilder<MemDb> {
    /// Finalizes the block building and returns the header
    pub fn finalize(&mut self) -> Result<Header> {
        let state_root = self.calculate_state_root()?;
        ensure!(self.input.block.state_root == state_root);
        Ok(self.input.block.header.clone())
    }

    /// Finalizes the block building and returns the header
    pub fn finalize_block(&mut self) -> Result<Block> {
        let state_root = self.calculate_state_root()?;
        ensure!(self.input.block.state_root == state_root);
        Ok(self.input.block.clone())
    }

    /// Calculates the state root of the block
    pub fn calculate_state_root(&mut self) -> Result<B256> {
        let mut account_touched = 0;
        let mut storage_touched = 0;

        // apply state updates
        let mut state_trie = mem::take(&mut self.input.parent_state_trie);
        for (address, account) in &self.db.as_ref().unwrap().accounts {
            // if the account has not been touched, it can be ignored
            if account.state == AccountState::None {
                continue;
            }

            // compute the index of the current account in the state trie
            let state_trie_index = keccak(address);

            // remove deleted accounts from the state trie
            if account.state == AccountState::Deleted {
                state_trie.delete(&state_trie_index)?;
                continue;
            }

            account_touched += 1;

            // otherwise, compute the updated storage root for that account
            let state_storage = &account.storage;
            let storage_root = {
                // getting a mutable reference is more efficient than calling remove
                // every account must have an entry, even newly created accounts
                let (storage_trie, _) = self
                    .input
                    .parent_storage
                    .get_mut(address)
                    .expect("Address not found in storage");
                // for cleared accounts always start from the empty trie
                if account.state == AccountState::StorageCleared {
                    storage_trie.clear();
                }

                // apply all new storage entries for the current account (address)
                for (key, value) in state_storage {
                    let storage_trie_index = keccak(key.to_be_bytes::<32>());
                    if value.is_zero() {
                        storage_trie.delete(&storage_trie_index)?;
                    } else {
                        storage_trie.insert_rlp(&storage_trie_index, *value)?;
                    }
                }

                storage_touched += 1;

                storage_trie.hash()
            };

            let state_account = StateAccount {
                nonce: account.info.nonce,
                balance: account.info.balance,
                storage_root,
                code_hash: account.info.code_hash,
            };
            state_trie.insert_rlp(&state_trie_index, state_account)?;
        }

        debug!("Accounts touched {account_touched:?}");
        debug!("Storages touched {storage_touched:?}");

        Ok(state_trie.hash())
    }
}

pub fn create_mem_db(input: &mut GuestInput) -> Result<MemDb> {
    // Verify state trie root
    if input.parent_state_trie.hash() != input.parent_header.state_root {
        bail!(
            "Invalid state trie: expected {}, got {}",
            input.parent_header.state_root,
            input.parent_state_trie.hash()
        );
    }

    // hash all the contract code
    let contracts: HashMap<B256, Bytes> = mem::take(&mut input.contracts)
        .into_iter()
        .map(|bytes| (keccak(&bytes).into(), bytes))
        .collect();

    let mut account_touched = 0;
    let mut storage_touched = 0;

    // Load account data into db
    let mut accounts = HashMap::with_capacity(input.parent_storage.len());
    for (address, (storage_trie, slots)) in &mut input.parent_storage {
        // consume the slots, as they are no longer needed afterwards
        let slots = mem::take(slots);

        account_touched += 1;

        // load the account from the state trie or empty if it does not exist
        let state_account = input
            .parent_state_trie
            .get_rlp::<StateAccount>(&keccak(address))?
            .unwrap_or_default();
        // Verify storage trie root
        if storage_trie.hash() != state_account.storage_root {
            bail!(
                "Invalid storage trie for {address:?}: expected {}, got {}",
                state_account.storage_root,
                storage_trie.hash()
            );
        }

        // load the corresponding code
        let code_hash = state_account.code_hash;
        let bytecode = if code_hash.0 == KECCAK_EMPTY.0 {
            Bytecode::new()
        } else {
            let bytes: Bytes = contracts
                .get(&code_hash)
                .expect(&format!("Contract {code_hash} of {address} exists"))
                .clone();
            Bytecode::new_raw(bytes)
        };

        // load storage reads
        let mut storage = HashMap::with_capacity(slots.len());
        for slot in slots {
            let value: U256 = storage_trie
                .get_rlp(&keccak(slot.to_be_bytes::<32>()))?
                .unwrap_or_default();
            storage.insert(slot, value);

            storage_touched += 1;
        }

        let mem_account = DbAccount {
            info: AccountInfo {
                balance: state_account.balance,
                nonce: state_account.nonce,
                code_hash: state_account.code_hash,
                code: Some(bytecode),
            },
            state: AccountState::None,
            storage,
        };

        accounts.insert(*address, mem_account);
    }
    guest_mem_forget(contracts);

    debug!("Accounts touched: {account_touched:?}");
    debug!("Storages touched: {storage_touched:?}");

    // prepare block hash history
    let mut block_hashes = HashMap::with_capacity(input.ancestor_headers.len() + 1);
    block_hashes.insert(input.parent_header.number, input.parent_header.hash_slow());
    let mut prev = &input.parent_header;
    for current in &input.ancestor_headers {
        let current_hash = current.hash_slow();
        if prev.parent_hash != current_hash {
            bail!(
                "Invalid chain: {} is not the parent of {}",
                current.number,
                prev.number
            );
        }
        if input.parent_header.number < current.number
            || input.parent_header.number - current.number >= MAX_BLOCK_HASH_AGE
        {
            bail!(
                "Invalid chain: {} is not one of the {MAX_BLOCK_HASH_AGE} most recent blocks",
                current.number,
            );
        }
        block_hashes.insert(current.number, current_hash);
        prev = current;
    }

    // Store database
    Ok(MemDb {
        accounts,
        block_hashes,
    })
}
