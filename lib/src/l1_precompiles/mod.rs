mod l1sload;
mod l1staticcall;
pub(crate) mod witness_db;

pub use l1sload::{
    acquire_l1sload_lock, build_verified_state_root_map, clear_l1sload_cache,
    populate_l1sload_cache, verify_and_populate_l1sload_proofs,
};

pub use l1staticcall::{
    verify_and_populate_l1_staticcall_witnesses,
    verify_and_populate_l1_staticcall_witnesses_with_headers,
};

/// Re-export L1 RPC fallback functions for L1SLOAD support
pub use alethia_reth_evm::precompiles::l1sload::{
    clear_l1_rpc_fetcher, clear_l1_rpc_served_calls, set_l1_rpc_fetcher, take_l1_rpc_served_calls,
};

/// Re-export L1STATICCALL RPC fallback functions
pub use alethia_reth_evm::precompiles::l1staticcall::{
    clear_l1_staticcall_cache, clear_l1_staticcall_rpc_fetcher,
    clear_l1_staticcall_rpc_served_calls, set_l1_staticcall_rpc_fetcher,
    take_l1_staticcall_rpc_served_calls,
};
