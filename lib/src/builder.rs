use core::mem;
use std::sync::Arc;
use std::sync::LazyLock;

use crate::block_executor::TaikoWithOptimisticBlockExecutor;
use crate::primitives::keccak::keccak;
use crate::primitives::mpt::StateAccount;
use crate::utils::{generate_transactions, generate_transactions_for_batch_blocks};
use crate::{
    consts::{ChainSpec, MAX_BLOCK_HASH_AGE},
    guest_mem_forget,
    input::{GuestBatchInput, GuestInput},
    l1_precompiles::verify_and_populate_l1sload_proofs,
    mem_db::{AccountState, DbAccount, MemDb},
    CycleTracker,
};
use alloy_primitives::map::HashMap;
use alloy_primitives::{Address, Bytes, B256, U256};
use anyhow::{bail, ensure, Result};
use reth_chainspec::Hardfork;
use reth_chainspec::{ChainHardforks, EthereumHardfork, ForkCondition, Hardforks};
use reth_consensus::{Consensus, HeaderValidator};
use reth_ethereum_consensus::validate_block_post_execution;
use reth_evm::block::BlockExecutionResult;
use reth_evm::execute::Executor;
use reth_evm::execute::{BlockExecutionOutput, ProviderError};
use reth_evm::Database;
use reth_primitives::RecoveredBlock;
use reth_primitives::SealedHeader;
use reth_primitives::{Block, Header, TransactionSigned};
use reth_storage_api::noop::NoopProvider;
use revm::primitives::KECCAK_EMPTY;
use revm::state::Account;
use revm::state::AccountInfo;
use revm::state::AccountStatus;
use revm::state::Bytecode;
use revm::state::EvmStorageSlot;
use revm::DatabaseCommit;
use taiko_reth::chainspec::hardfork::TaikoHardfork;
use taiko_reth::chainspec::spec::TaikoChainSpec;
use taiko_reth::chainspec::TAIKO_DEVNET;
use taiko_reth::chainspec::TAIKO_MAINNET;
use taiko_reth::consensus::validation::TaikoBeaconConsensus;
use taiko_reth::evm::config::TaikoEvmConfig;
use taiko_reth::evm::factory::TaikoEvmFactory;
use taiko_reth::evm::spec::TaikoSpecId;
use tracing::{debug, info};

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
                activation_block_number: 0,
            },
        ),
        (
            EthereumHardfork::Shanghai.boxed(),
            ForkCondition::Timestamp(0),
        ),
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
                activation_block_number: 0,
            },
        ),
        (
            EthereumHardfork::Shanghai.boxed(),
            ForkCondition::Timestamp(0),
        ),
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
                activation_block_number: 0,
            },
        ),
        (
            EthereumHardfork::Shanghai.boxed(),
            ForkCondition::Timestamp(0),
        ),
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

pub fn calculate_block_header(input: &GuestInput) -> Header {
    let cycle_tracker = CycleTracker::start("initialize_database");
    let db = create_mem_db(&mut input.clone()).unwrap();
    cycle_tracker.end();

    if !input.l1_storage_proofs.is_empty() {
        let anchor_state_root = input.taiko.l1_header.state_root;
        verify_and_populate_l1sload_proofs(&input.l1_storage_proofs, anchor_state_root)
            .expect("Failed to verify and populate L1SLOAD proofs for block");
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
            verify_and_populate_l1sload_proofs(
                &input.inputs[i].l1_storage_proofs,
                anchor_state_root,
            )
            .expect(&format!(
                "Failed to verify and populate L1SLOAD proofs for batch block #{}",
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

impl<DB: Database<Error = ProviderError> + DatabaseCommit + OptimisticDatabase + Clone>
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
        let chain_spec = match chain_spec.name.as_str() {
            "taiko_mainnet" => TAIKO_MAINNET.clone(),
            "taiko_dev" => TAIKO_DEVNET.clone(),
            "surge_dev" => SURGE_DEV.clone(),
            "surge_test" => SURGE_TEST.clone(),
            "surge_stage" => SURGE_STAGE.clone(),
            "surge_mainnet" => SURGE_MAINNET.clone(),
            _ => unimplemented!(),
        };

        info!("execute_transactions: reth_chain_spec done");

        let block_num = self.input.taiko.block_proposed.block_number();
        // let block_timestamp = 0u64;
        let block_timestamp = self.input.taiko.block_proposed.block_timestamp();

        let taiko_fork = self
            .input
            .chain_spec
            .spec_id(block_num, block_timestamp)
            .unwrap();

        match taiko_fork {
            TaikoSpecId::ONTAKE => {
                assert!(
                    chain_spec
                        .fork(TaikoHardfork::Ontake)
                        .active_at_block(block_num),
                    "evm fork ONTAKE is not active, please update the chain spec"
                );
            }
            TaikoSpecId::PACAYA => {
                assert!(
                    chain_spec
                        .fork(TaikoHardfork::Pacaya)
                        .active_at_block(block_num),
                    "evm fork PACAYA is not active, please update the chain spec"
                );
            }
            _ => unimplemented!(),
        }
        info!("execute_transactions: is_taiko done");

        // Generate the transactions from the tx list
        let mut block = self.input.block.clone();
        block.body.transactions = pool_txs;

        let taiko_evm_config = TaikoEvmConfig::new_with_evm_factory(
            chain_spec.clone(),
            TaikoEvmFactory::new(Some(Address::ZERO)), // TODO: make it configurable
        );

        // TODO: Maybe remove as "prover" feature has been added to taiko-reth?
        let executor = TaikoWithOptimisticBlockExecutor::new(
            taiko_evm_config,
            self.db.take().unwrap(),
            optimistic,
        );

        // Recover senders
        let recovered_block = RecoveredBlock::try_recover(block)?;

        let mut tmp_db = None;
        let BlockExecutionOutput {
            state,
            result:
                BlockExecutionResult {
                    receipts,
                    requests,
                    gas_used: _,
                },
        } = executor.execute_with_state_closure(&recovered_block, |state| {
            tmp_db = Some(state.database.clone());
        })?;

        info!("execute_transactions: execute done");

        // Filter out the valid transactions so that the header checks only take these into account
        let mut block = recovered_block.into_block();

        let (filtered_txs, _): (Vec<_>, Vec<_>) = block
            .body
            .transactions
            .into_iter()
            .zip(receipts.clone())
            .filter(|(_, receipt)| receipt.success || (!receipt.success && optimistic))
            .unzip();

        block.body.transactions = filtered_txs;

        let recovered_block = RecoveredBlock::try_recover(block)?;
        let sealed_block = recovered_block.sealed_block();
        let sealed_header = sealed_block.sealed_header();

        info!("execute_transactions: valid_transaction_indices done");
        // Header validation
        if !optimistic {
            // TODO: change NoopProvider for Shasta
            let consensus = TaikoBeaconConsensus::new(chain_spec.clone(), NoopProvider::default());
            // Validates if some values are set that should not be set for the current HF
            consensus.validate_header(sealed_header)?;
            info!("execute_transactions: validate_header done");
            // Validates parent block hash, block number and timestamp
            let parent_sealed_header = SealedHeader::new_unhashed(self.input.parent_header.clone());
            consensus.validate_header_against_parent(sealed_header, &parent_sealed_header)?;
            info!("execute_transactions: validate_header_against_parent done");
            // Validates ommers hash, transaction root, withdrawals root
            consensus.validate_block_pre_execution(sealed_block)?;
            info!("execute_transactions: validate_block_pre_execution done");
            // Validates the gas used, the receipts root and the logs bloom
            validate_block_post_execution(&recovered_block, &chain_spec, &receipts, &requests)?;
            info!("execute_transactions: validate_block_post_execution done");
        }

        // Apply DB change
        self.db = tmp_db;
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
                                    transaction_id: 0,
                                    // is_cold used in EIP-2929 for optimizing gas costs for slot accesses, we don't need this in proving
                                    is_cold: false,
                                },
                            )
                        })
                        .collect(),
                    status: AccountStatus::default(),
                    transaction_id: 0,
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
