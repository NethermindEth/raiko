//! Aggregates multiple batch proofs (verification handled by the host).

#![no_main]
ziskos::entrypoint!(main);

mod precompile_shims;
mod ruint_shims;

use raiko_lib::{
    input::ZkAggregationGuestInput,
    primitives::B256,
    protocol_instance::{aggregation_output, words_to_bytes_le},
};

pub fn main() {
    // Read the aggregation input data from ziskos
    let input_data = ziskos::io::read_vec();
    assert!(!input_data.is_empty(), "aggregation input is empty");

    // Deserialize input using the standard ZkAggregationGuestInput format
    let input: ZkAggregationGuestInput =
        bincode::deserialize(&input_data).expect("failed to deserialize ZkAggregationGuestInput");

    assert!(
        !input.block_inputs.is_empty(),
        "aggregation input has no block inputs"
    );

    // Use the same aggregation_output function for consistency
    let program_id = B256::from(words_to_bytes_le(&input.image_id));
    let aggregated_output = aggregation_output(program_id, input.block_inputs.clone());

    // Commit the aggregation output as public output
    ziskos::io::write(&aggregated_output);
}
