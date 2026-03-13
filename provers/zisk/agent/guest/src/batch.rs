#![no_main]
ziskos::entrypoint!(main);

// v0.16.0: patch crates removed — ziskos provides native precompile implementations.
// These shims were needed for the 0.15.0 patch crates (k256, sha2, ruint) which
// called extern "C" functions. Kept for reference if custom shims are needed later.
// mod precompile_shims;
// mod ruint_shims;

use raiko_lib::{
    builder::calculate_batch_blocks_final_header, input::GuestBatchInput, proof_type::ProofType,
    protocol_instance::ProtocolInstance,
};

pub fn main() {
    // Read the batch input data from ziskos
    let input_data = ziskos::io::read_vec();

    // Deserialize the batch input using the standard GuestBatchInput format
    let mut batch_input: GuestBatchInput =
        bincode::deserialize(&input_data).expect("failed to deserialize GuestBatchInput");

    // This executes all transactions and validates state transitions
    let final_blocks = calculate_batch_blocks_final_header(&mut batch_input);

    // Create protocol instance from executed blocks
    let protocol_instance =
        ProtocolInstance::new_batch(&batch_input, final_blocks, ProofType::Zisk)
            .expect("failed to build Zisk protocol instance");

    // Get the instance hash and commit as public output
    let instance_hash = protocol_instance.instance_hash();
    ziskos::io::write(&instance_hash.0);
}
