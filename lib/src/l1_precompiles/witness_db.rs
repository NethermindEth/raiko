/// WitnessDb — a minimal `reth_revm::Database` backed by a parsed execution witness.
///
/// This is Layer-3 code specific to our single-call re-execution.
/// It wraps the MPT tries produced by `witness_to_tries` and serves account info,
/// storage, and code to revm during re-execution of an L1 staticcall.
use std::collections::HashMap;

use alloy_primitives::{Address, Bytes, B256, U256};
use anyhow::{Context, Result};
use reth_evm::execute::ProviderError;
use reth_revm::Database;
use revm::state::{AccountInfo, Bytecode};
use tracing::debug;

use crate::input::ExecutionWitness;
use crate::primitives::mpt::{keccak, MptNode, StateAccount, StorageEntry, KECCAK_EMPTY};
use crate::primitives::witness::witness_to_tries;

/// A read-only database built from an `ExecutionWitness`, for single-call re-execution.
pub struct WitnessDb {
    state_trie: MptNode,
    storage: HashMap<Address, StorageEntry>,
    /// Contract bytecodes keyed by code_hash.
    codes: HashMap<B256, Bytes>,
    /// Block hashes from witnessed headers.
    block_hashes: HashMap<u64, B256>,
}

impl WitnessDb {
    /// Builds a `WitnessDb` from a raw `ExecutionWitness`, verifying the state root.
    pub fn build(witness: &ExecutionWitness, state_root: B256) -> Result<Self> {
        let (state_trie, storage) = witness_to_tries(state_root, witness)?;

        let mut codes: HashMap<B256, Bytes> = HashMap::new();
        for raw_code in &witness.codes {
            let hash: B256 = keccak(raw_code.as_ref()).into();
            codes.insert(hash, raw_code.clone());
        }

        let mut block_hashes: HashMap<u64, B256> = HashMap::new();
        for header_bytes in &witness.headers {
            let header: reth_primitives::Header =
                alloy_rlp::Decodable::decode(&mut header_bytes.as_ref())
                    .context("Failed to RLP-decode witness header")?;
            let header_hash = alloy_primitives::keccak256(header_bytes.as_ref());
            block_hashes.insert(header.number, header_hash);
        }

        Ok(Self {
            state_trie,
            storage,
            codes,
            block_hashes,
        })
    }

    /// Retrieves a decoded header at the given block number, if present.
    pub fn header_at(&self, block_number: u64) -> Option<B256> {
        self.block_hashes.get(&block_number).copied()
    }

    /// Missing accounts resolve to `None`, matching L1 semantics for "account does not
    /// exist". The later output/gas assertion is what catches an actually incomplete witness.
    fn lookup_account(&self, address: Address) -> Result<Option<StateAccount>, ProviderError> {
        let key = keccak(address);
        match self.state_trie.get(&key) {
            Ok(Some(rlp_bytes)) => {
                let account: StateAccount = alloy_rlp::Decodable::decode(&mut &rlp_bytes[..])
                    .map_err(|_| ProviderError::BestBlockNotFound)?;
                Ok(Some(account))
            }
            Ok(None) => Ok(None),
            Err(_) => {
                debug!("WitnessDb: unresolved trie node for account {address}");
                Ok(None)
            }
        }
    }
}

impl Database for WitnessDb {
    type Error = ProviderError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        match self.lookup_account(address)? {
            Some(state_account) => {
                let code = if state_account.code_hash != KECCAK_EMPTY {
                    self.codes
                        .get(&state_account.code_hash)
                        .map(|b| Bytecode::new_raw(alloy_primitives::Bytes::from(b.to_vec())))
                } else {
                    None
                };

                Ok(Some(AccountInfo {
                    nonce: state_account.nonce,
                    balance: state_account.balance,
                    code_hash: state_account.code_hash,
                    // `account_id` is a revm optimization hint (account index in the
                    // block-access list); we don't have one — None is safe and correct.
                    account_id: None,
                    code,
                }))
            }
            None => {
                debug!("WitnessDb::basic: account {address} not in witness");
                Ok(None)
            }
        }
    }

    /// Missing code is a hard error: absent bytecode always changes call behavior, so we
    /// must fail loudly instead of pretending the contract is empty.
    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        match self.codes.get(&code_hash) {
            Some(code) => Ok(Bytecode::new_raw(alloy_primitives::Bytes::from(
                code.to_vec(),
            ))),
            None => {
                debug!("WitnessDb::code_by_hash: code {code_hash} not in witness");
                Err(ProviderError::BestBlockNotFound)
            }
        }
    }

    /// Missing storage resolves to zero, matching L1 semantics for an absent slot/account.
    /// The separate three-way `(output, gas_used, halt status)` assertion catches witnesses
    /// that are incomplete in a behavior-changing way.
    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        if let Some((storage_trie, _slots)) = self.storage.get(&address) {
            let key = keccak(index.to_be_bytes::<32>());
            match storage_trie.get(&key) {
                Ok(Some(rlp_bytes)) => {
                    let value: U256 = alloy_rlp::Decodable::decode(&mut &rlp_bytes[..])
                        .map_err(|_| ProviderError::BestBlockNotFound)?;
                    Ok(value)
                }
                Ok(None) => Ok(U256::ZERO),
                Err(_) => {
                    debug!("WitnessDb::storage: unresolved trie node for {address} slot {index}");
                    Ok(U256::ZERO)
                }
            }
        } else {
            debug!("WitnessDb::storage: account {address} not in witness, returning zero");
            Ok(U256::ZERO)
        }
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.block_hashes
            .get(&number)
            .copied()
            .ok_or(ProviderError::BestBlockNotFound)
    }
}
