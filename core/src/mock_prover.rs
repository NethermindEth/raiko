use alloy_primitives::B256;
use raiko_lib::{
    input::{
        AggregationGuestInput, AggregationGuestOutput, GuestBatchInput, GuestBatchOutput,
        GuestInput, GuestOutput, ShastaAggregationGuestInput,
    },
    libhash::hash_commitment,
    primitives::{keccak256, Signature},
    proof_type::ProofType,
    protocol_instance::{aggregation_output, build_shasta_commitment_from_proof_carry_data_vec},
    prover::{
        IdStore, IdWrite, Proof, ProofCarryData, ProofKey, Prover, ProverConfig, ProverError,
        ProverResult,
    },
};
use secp256k1::{Message, SecretKey, SECP256K1};
use tracing::trace;

pub struct MockProver(B256);

impl MockProver {
    pub fn new(mock_key: String) -> ProverResult<Self> {
        // Parse the private key from hex string (with or without 0x prefix)
        let key_bytes = alloy_primitives::hex::decode(&mock_key)
            .map_err(|e| ProverError::Other(format!("Invalid hex in mock key: {}", e)))?;
        let key_b256 = B256::from_slice(&key_bytes);

        Ok(Self(key_b256))
    }

    /// Sign a hash using the private key stored in the MockProver.
    /// This implementation follows the same pattern as the SGX prover's sign_message function.
    fn sign_hash(&self, hash: &B256) -> Result<Signature, String> {
        // Create SecretKey from the stored B256 key
        let secret_key = SecretKey::from_slice(self.0.as_slice())
            .map_err(|e| format!("Invalid secret key: {}", e))?;

        // Sign the hash
        let message = Message::from_digest_slice(hash.as_slice())
            .map_err(|e| format!("Invalid message digest: {}", e))?;

        let sig = SECP256K1.sign_ecdsa_recoverable(&message, &secret_key);
        let (rec_id, data) = sig.serialize_compact();

        // Convert to Signature with recovery ID for Ethereum compatibility
        let signature = Signature::from_bytes_and_parity(&data, Into::<i32>::into(rec_id) != 0i32);

        Ok(signature)
    }
}

impl Prover for MockProver {
    async fn get_guest_data() -> ProverResult<serde_json::Value> {
        unimplemented!()
    }

    /// Run the prover for Shasta proposals (delegates to batch_run for now)
    async fn proposal_run(
        &self,
        input: GuestBatchInput,
        output: &GuestBatchOutput,
        config: &ProverConfig,
        store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        // Default implementation delegates to batch_run
        self.batch_run(input.clone(), output, config, store).await
    }

    async fn run(
        &self,
        _input: GuestInput,
        _output: &GuestOutput,
        _config: &ProverConfig,
        _store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        unimplemented!("MockProver does not support single run");
    }

    async fn batch_run(
        &self,
        batch_input: GuestBatchInput,
        batch_output: &GuestBatchOutput,
        _config: &ProverConfig,
        _store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        trace!("Running the mock prover for batch input: {batch_input:?}");

        // Sign the batch output hash using the private key
        let signature = self
            .sign_hash(&batch_output.hash)
            .map_err(|e| ProverError::GuestError(format!("Failed to sign hash: {}", e)))?;

        // Encode signature as hex string
        let proof_data = alloy_primitives::hex::encode_prefixed(signature.as_bytes());

        Ok(Proof {
            input: Some(batch_output.hash),
            proof: Some(proof_data),
            quote: None,
            uuid: None,
            kzg_proof: None,
            extra_data: None,
        })
    }

    async fn cancel(&self, _proof_key: ProofKey, _read: Box<&mut dyn IdStore>) -> ProverResult<()> {
        Ok(())
    }

    async fn aggregate(
        &self,
        input: AggregationGuestInput,
        _output: &AggregationGuestOutput,
        _config: &ProverConfig,
        _store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        trace!("Running the mock prover for aggregation input");

        // Extract block inputs from the proofs
        let block_inputs: Vec<B256> = input
            .proofs
            .iter()
            .map(|proof| proof.input.unwrap())
            .collect();

        // For mock mode, use a dummy program hash (all zeros)
        let program_hash = B256::ZERO;

        // Generate the same aggregation output as in aggregation.rs
        let aggregation_output_bytes = aggregation_output(program_hash, block_inputs);

        // Hash the aggregation output to get the message to sign
        let message_hash = keccak256(&aggregation_output_bytes);

        // Sign the message hash using the private key
        let signature = self
            .sign_hash(&message_hash)
            .map_err(|e| ProverError::GuestError(format!("Failed to sign aggregation: {}", e)))?;

        // Encode signature as hex string
        let proof_data = alloy_primitives::hex::encode_prefixed(signature.as_bytes());

        Ok(Proof {
            input: Some(message_hash),
            proof: Some(proof_data),
            quote: None,
            uuid: None,
            kzg_proof: None,
            extra_data: None,
        })
    }

    async fn shasta_aggregate(
        &self,
        input: ShastaAggregationGuestInput,
        _output: &AggregationGuestOutput,
        _config: &ProverConfig,
        _store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        trace!("Running the mock prover for aggregation input");

        // Extract the useful parts of the proof
        let proof_carry_data_vec: Vec<_> = input
            .proofs
            .iter()
            .map(|proof| {
                let extra_data = proof.extra_data.clone().unwrap();
                ProofCarryData {
                    chain_id: extra_data.chain_id,
                    verifier: extra_data.verifier,
                    transition_input: extra_data.transition_input,
                }
            })
            .collect();

        let commitment_hash = hash_commitment(
            &build_shasta_commitment_from_proof_carry_data_vec(&proof_carry_data_vec).ok_or(
                ProverError::GuestError("Failed to build shasta commitment".to_string()),
            )?,
        );

        // Sign the message hash using the private key
        let signature = self
            .sign_hash(&commitment_hash)
            .map_err(|e| ProverError::GuestError(format!("Failed to sign aggregation: {}", e)))?;

        // Encode signature as hex string
        let proof_data = alloy_primitives::hex::encode_prefixed(signature.as_bytes());

        Ok(Proof {
            input: Some(commitment_hash),
            proof: Some(proof_data),
            quote: None,
            uuid: None,
            kzg_proof: None,
            extra_data: None,
        })
    }

    fn proof_type(&self) -> ProofType {
        unimplemented!("MockProver does not define a proof type");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use raiko_lib::primitives::keccak256;
    use secp256k1::{
        ecdsa::{RecoverableSignature, RecoveryId},
        Message, PublicKey,
    };

    /// Helper function to recover address from signature
    fn recover_address(signature: &Signature, message: &B256) -> Result<Address, String> {
        let sig_bytes = signature.as_bytes();
        let v = sig_bytes[64];
        let recovery_id = RecoveryId::try_from((v as i32) - 27)
            .map_err(|e| format!("Invalid recovery id: {}", e))?;

        let recoverable_sig = RecoverableSignature::from_compact(&sig_bytes[..64], recovery_id)
            .map_err(|e| format!("Failed to create recoverable signature: {}", e))?;

        let message = Message::from_digest_slice(message.as_slice())
            .map_err(|e| format!("Invalid message: {}", e))?;

        let public_key = SECP256K1
            .recover_ecdsa(&message, &recoverable_sig)
            .map_err(|e| format!("Failed to recover public key: {}", e))?;

        Ok(public_key_to_address(&public_key))
    }

    /// Convert public key to Ethereum address
    fn public_key_to_address(public_key: &PublicKey) -> Address {
        let hash = keccak256(&public_key.serialize_uncompressed()[1..]);
        Address::from_slice(&hash[12..])
    }

    #[test]
    fn test_sign_hash_with_known_key() {
        // Known test private key (DO NOT use in production!)
        let private_key = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let expected_address: Address = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
            .parse()
            .unwrap();

        let prover = MockProver::new(private_key.to_string()).unwrap();

        // Test message hash
        let message_hash = B256::from_slice(&[0x42; 32]);

        // Sign the hash
        let signature = prover
            .sign_hash(&message_hash)
            .expect("Signing should succeed");

        // Verify the signature is 65 bytes
        assert_eq!(signature.as_bytes().len(), 65);

        // Recover the address from the signature
        let recovered_address =
            recover_address(&signature, &message_hash).expect("Recovery should succeed");

        // Verify the recovered address matches the expected address
        assert_eq!(
            recovered_address, expected_address,
            "Recovered address should match the expected address"
        );
    }

    #[test]
    fn test_sign_hash_invalid_key() {
        // Invalid key (not 32 bytes)
        let prover = MockProver::new("invalid".to_string());

        assert!(prover.is_err(), "Should fail with invalid key");
    }
}
