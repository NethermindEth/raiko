mod l1sload;

pub use l1sload::{
    acquire_l1sload_lock, clear_l1sload_cache, populate_l1sload_cache,
    verify_and_populate_l1sload_proofs,
};

/// Re-export L1 RPC fallback functions for L1SLOAD support
pub use alethia_reth_evm::precompiles::l1sload::{
    clear_l1_rpc_fetcher, clear_l1_rpc_served_calls, set_l1_rpc_fetcher, take_l1_rpc_served_calls,
};
