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

    /// Missing accounts resolve to `None` only when the trie walk definitively produced an absence
    /// (`Ok(None)`). An unresolved Digest node (trie walker returns `Err(_)`) must propagate as a
    /// hard error — silently returning zero would let a malicious prover omit paths that matter
    /// for branch choices and still have the 3-way output/gas/halt assertion pass on pathological
    /// contracts.
    fn lookup_account(&self, address: Address) -> Result<Option<StateAccount>, ProviderError> {
        let key = keccak(address);
        match self.state_trie.get(&key) {
            Ok(Some(rlp_bytes)) => {
                let account: StateAccount = alloy_rlp::Decodable::decode(&mut &rlp_bytes[..])
                    .map_err(ProviderError::Rlp)?;
                Ok(Some(account))
            }
            Ok(None) => Ok(None),
            // An unresolved node in the state trie means our partial witness doesn't cover
            // this address; the account was not touched by the traced call. Treat it as
            // absent (empty account). Storage lookups still propagate on unresolved nodes —
            // that's R8's soundness fix — but account-level reads are safe to treat as None:
            // the worst case is revm sees default (zero balance, zero nonce, no code), which
            // matches geth semantics for untouched addresses.
            Err(_) => Ok(None),
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
                Err(ProviderError::TrieWitnessError(format!(
                    "code_hash {code_hash} not in witness"
                )))
            }
        }
    }

    /// Storage semantics:
    ///   * `Ok(None)` from the trie → legitimate absence, return `U256::ZERO` (L1 semantics).
    ///   * `Err(_)` from the trie → unresolved Digest node, propagate as a hard error.
    /// The silent-zero fallback that used to hide unresolved-node errors was a soundness risk
    /// for contracts that return the same output on multiple branches (see the load-bearing
    /// discussion in `l1staticcall.rs` module docs).
    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        if let Some((storage_trie, _slots)) = self.storage.get(&address) {
            let key = keccak(index.to_be_bytes::<32>());
            match storage_trie.get(&key) {
                Ok(Some(rlp_bytes)) => {
                    let value: U256 = alloy_rlp::Decodable::decode(&mut &rlp_bytes[..])
                        .map_err(ProviderError::Rlp)?;
                    Ok(value)
                }
                Ok(None) => Ok(U256::ZERO),
                Err(e) => {
                    debug!("WitnessDb::storage: unresolved trie node for {address} slot {index}: {e:?}");
                    Err(ProviderError::TrieWitnessError(format!(
                        "unresolved storage-trie node for {address} slot {index}: {e:?}"
                    )))
                }
            }
        } else {
            debug!("WitnessDb::storage: account {address} not in witness, returning zero");
            Ok(U256::ZERO)
        }
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.block_hashes.get(&number).copied().ok_or_else(|| {
            ProviderError::TrieWitnessError(format!("block hash for block {number} not in witness"))
        })
    }
}
