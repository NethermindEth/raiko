use alloy_primitives::{Address, B256};
use reth_revm::{
    context_interface::ContextTr,
    interpreter::{CallInputs, CallOutcome},
    Inspector,
};
use std::collections::HashSet;

/// L1SLOAD precompile address from RIP-7728 (0x0000000000000000000000000000000000010001)
pub const L1SLOAD_ADDRESS: Address = Address::new([
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0, 0x01,
]);

/// Inspector that tracks all calls to the L1SLOAD precompile.
///
/// Detects L1SLOAD calls with the full 84-byte input format:
/// - [0:20]  = contract address (20 bytes)
/// - [20:52] = storage key (32 bytes)
/// - [52:84] = L1 block number (32 bytes, big-endian B256)
#[derive(Debug, Default, Clone)]
pub struct L1SloadInspector {
    /// Set of (contract_address, storage_key, block_number) tuples detected during execution
    pub detected_calls: HashSet<(Address, B256, B256)>,
}

impl L1SloadInspector {
    pub fn new() -> Self {
        Self {
            detected_calls: HashSet::new(),
        }
    }

    /// Get all detected L1SLOAD calls
    pub fn get_detected_calls(&self) -> &HashSet<(Address, B256, B256)> {
        &self.detected_calls
    }
}

impl<CTX: ContextTr, INTR: reth_revm::interpreter::InterpreterTypes> Inspector<CTX, INTR>
    for L1SloadInspector
{
    /// Called whenever a call to a contract is about to start.
    ///
    /// Returning `CallOutcome` will override the result of the call.
    #[inline]
    fn call(&mut self, context: &mut CTX, inputs: &mut CallInputs) -> Option<CallOutcome> {
        // Check if this is a call to the L1SLOAD precompile
        if inputs.target_address == L1SLOAD_ADDRESS {
            // L1SLOAD input format (84 bytes):
            // [0:20]   = contract address (20 bytes)
            // [20:52]  = storage key (32 bytes)
            // [52:84]  = L1 block number (32 bytes, big-endian B256)

            // Get the actual bytes from CallInput (handles both SharedBuffer and Bytes variants)
            let input_bytes = inputs.input.bytes(context);

            if input_bytes.len() == 84 {
                let contract_address = Address::from_slice(&input_bytes[0..20]);
                let storage_key = B256::from_slice(&input_bytes[20..52]);
                let block_number = B256::from_slice(&input_bytes[52..84]);

                // Track this L1SLOAD call
                self.detected_calls
                    .insert((contract_address, storage_key, block_number));
            }
        }

        None
    }
}
