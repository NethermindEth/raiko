#![no_main]
ziskos::entrypoint!(main);

mod precompile_shims;
mod ruint_shims;

use raiko_lib::{
    builder::calculate_batch_blocks_final_header, input::GuestBatchInput, proof_type::ProofType,
    protocol_instance::ProtocolInstance,
};

pub fn main() {
    // // Route ecrecover through the ziskos high-level syscall instead of the
    // // k256 patch field-op path (reduces ROM size from ~500+ calls to 1).
    // raiko_lib::revm::precompile::install_crypto(zisk_crypto::ZiskCrypto);
    // let crypto = Arc::new(zisk_crypto::ZiskCrypto);
    // raiko_lib::alloy_consensus::crypto::install_default_provider(crypto.clone())
    //     .expect("crypto provider already set");

    // Initialize hints stream (native build only — emits precompile hint requests)
    #[cfg(zisk_hints)]
    ziskos::hints::init_hints_file("/tmp/zisk-hints.bin".into(), None)
        .expect("failed to init hints");

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

    // Close hints stream (flushes all pending hints)
    #[cfg(zisk_hints)]
    ziskos::hints::close_hints().expect("failed to close hints");
}
