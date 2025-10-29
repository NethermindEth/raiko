#![no_main]
harness::entrypoint!(main, tests, zk_op::tests);
use raiko_lib::{
    builder::calculate_block_header, input::GuestInput, proof_type::ProofType,
    protocol_instance::ProtocolInstance,
};
use risc0_zkvm::guest::env;

// deprecated after pacaya
fn main() {
    let input: GuestInput = env::read();

    let header = calculate_block_header(&input);
    let pi = ProtocolInstance::new(&input, &header, ProofType::Risc0)
        .unwrap()
        .instance_hash();

    env::commit(&pi);
}

harness::zk_suits!(
    pub mod tests {
        #[test]
        pub fn test_build_from_mock_input() {
            // Todo: impl mock input for static unit test
            assert_eq!(1, 1);
        }
    }
);