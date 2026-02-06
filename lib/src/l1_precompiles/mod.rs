mod l1sload;

pub use l1sload::{
    clear_l1sload_cache, populate_l1sload_cache, verify_and_populate_l1sload_proofs,
};

/// Re-export the max lookback constant for use in preflight and detection
pub use alethia_reth_evm::precompiles::l1sload::L1SLOAD_MAX_BLOCK_LOOKBACK;
