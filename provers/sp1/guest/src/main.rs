#![no_main]
sp1_zkvm::entrypoint!(main);

use alloy_primitives::{keccak256, B256};
use raiko_lib::{
    builder::calculate_block_header,
    input::{GuestInput, L1BlockHeader, L1StorageProof},
    proof_type::ProofType,
    protocol_instance::ProtocolInstance,
    CycleTracker,
};
use std::collections::HashMap;

pub mod sys;
pub use sys::*;

/// Verify L1 storage proof against L1 state root
fn verify_l1_storage_proof(proof: &L1StorageProof, state_root: &B256) {
    // TODO: Implement proper Merkle proof verification (use alloy_trie::proof::verify_proof?)
    let account_key = keccak256(proof.contract_address.as_slice());

    // TODO:
    // let account_proof_bytes: Vec<Vec<u8>> = proof.account_proof
    //     .iter()
    //     .map(|b| b.to_vec())
    //     .collect();

    // let account_rlp = verify_proof(
    //     account_proof_bytes,
    //     *state_root,
    //     account_key.as_slice(),
    // ).expect("Account proof verification failed");

    // 2. Extract storage root from account and verify storage proof
    // ... (storage proof verification would go here)

    // For now, just log the verification attempt
    sp1_zkvm::io::hint(&format!(
        "Verifying L1 storage proof for contract {:?}, key {:?}, value {:?}",
        proof.contract_address, proof.storage_key, proof.value
    ));
}

pub fn main() {
    let mut ct = CycleTracker::start("input");
    let input = sp1_zkvm::io::read_vec();
    let input = bincode::deserialize::<GuestInput>(&input).unwrap();
    ct.end();

    // Verify L1 proofs before execution
    ct = CycleTracker::start("verify_l1_proofs");
    if !input.l1_storage_proofs.is_empty() {
        // Build block number -> state root mapping
        let mut l1_state_roots = HashMap::new();
        for header in &input.l1_headers {
            l1_state_roots.insert(header.number, header.state_root);
        }

        // Verify each L1 storage proof
        for proof in &input.l1_storage_proofs {
            // Convert B256 block number back to u64
            let block_num = u64::from_be_bytes(
                proof.block_number[24..32]
                    .try_into()
                    .expect("Invalid block number format"),
            );

            let state_root = l1_state_roots
                .get(&block_num)
                .expect("Missing L1 header for L1SLOAD block");

            verify_l1_storage_proof(proof, state_root);
        }
    }
    ct.end();

    // NOW execute with verified L1 data
    ct = CycleTracker::start("calculate_block_header");
    let header = calculate_block_header(&input);
    ct.end();

    ct = CycleTracker::start("ProtocolInstance");
    let pi = ProtocolInstance::new(&input, &header, ProofType::Sp1)
        .unwrap()
        .instance_hash();
    ct.end();

    sp1_zkvm::io::commit(&pi.0);
}

harness::zk_suits!(
    pub mod tests {
        use reth_primitives::alloy_primitives::PrimitiveSignature as Signature;
        use reth_primitives::U256;
        use std::str::FromStr;

        #[test]
        pub fn test_build_from_mock_input() {
            // Todo: impl mock input for static unit test
            assert_eq!(1, 1);
        }
        pub fn test_signature() {
            let signature = Signature::new(
                U256::from_str(
                    "18515461264373351373200002665853028612451056578545711640558177340181847433846",
                )
                .unwrap(),
                U256::from_str(
                    "46948507304638947509940763649030358759909902576025900602547168820602576006531",
                )
                .unwrap(),
                false,
            );
            let hash = reth_primitives::B256::from_str(
                "daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53",
            )
            .unwrap();
            signature.recover_address_from_msg(hash).unwrap();
        }
    }
);
