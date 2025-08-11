
use anyhow::{anyhow, Result};
use raiko_lib::{
    input::{AggregationGuestInput, GuestInput, RawAggregationGuestInput},
    primitives::{Address, B256, keccak::keccak},
    proof_type::ProofType,
    protocol_instance::{aggregation_output_combine, ProtocolInstance},
};
use rand::Rng;
use tracing::info;

use crate::{
    attestation_client,
    config::{load_instance_id, load_private_key},
    signature::{get_address_from_private_key, recover_signer_unchecked, sign_message},
    TdxConfig, TdxProverData, TdxQuote, TDX_AGGREGATION_PROOF_SIZE, TDX_PROOF_SIZE,
};

pub fn create_proof(instance_id: u32, public_key: &Address, signature: &[u8; 65]) -> Result<Vec<u8>> {
    let mut proof = Vec::with_capacity(TDX_PROOF_SIZE);
    
    proof.extend_from_slice(&instance_id.to_be_bytes());
    proof.extend_from_slice(public_key.as_slice());
    proof.extend_from_slice(signature);
    
    Ok(proof)
}

pub fn create_aggregation_proof(
    instance_id: u32,
    old_instance: &Address,
    new_instance: &Address,
    signature: &[u8; 65],
) -> Result<Vec<u8>> {
    let mut proof = Vec::with_capacity(TDX_AGGREGATION_PROOF_SIZE);

    proof.extend_from_slice(&instance_id.to_be_bytes());
    proof.extend_from_slice(old_instance.as_slice());
    proof.extend_from_slice(new_instance.as_slice());
    proof.extend_from_slice(signature);

    Ok(proof)
}

pub fn generate_tdx_quote(user_report_data: &B256, socket_path: &str) -> Result<TdxQuote> {
    let user_data = user_report_data.as_slice();
    let nonce: [u8; 32] = rand::thread_rng().gen();
    let nonce = nonce.to_vec();

    info!("Using external attestation service at: {}", socket_path);
    
    let attestation_doc = attestation_client::issue_attestation(socket_path, user_data, &nonce)?;

    Ok(TdxQuote {
        data: attestation_doc,
    })
}

pub fn generate_tdx_quote_from_public_key(public_key: &Address, socket_path: &str) -> Result<TdxQuote> {
    let bootstrap_data = public_key.to_vec();
    let mut padded_data = [0u8; 32];
    padded_data[..bootstrap_data.len().min(32)].copy_from_slice(&bootstrap_data[..bootstrap_data.len().min(32)]);

    generate_tdx_quote(&B256::from_slice(&padded_data), socket_path)
}

pub struct ProveData {
    pub proof: Vec<u8>,
    pub quote: TdxQuote,
    pub address: Address,
    pub instance_hash: B256,
}

pub fn prove(
    input: &GuestInput,
    tdx_config: &TdxConfig,
) -> Result<ProveData> {
    let private_key = load_private_key()?;
    let address = get_address_from_private_key(&private_key)?;
    let instance_id = load_instance_id().unwrap_or(tdx_config.instance_id);
    
    let pi = ProtocolInstance::new(&input, &input.block.header, ProofType::Tdx)?
        .sgx_instance(address);

    let pi_hash = pi.instance_hash();
    let signature = sign_message(&private_key, &pi_hash)?;
    let proof = create_proof(instance_id, &address, &signature)?;
    let quote = generate_tdx_quote(&pi_hash, &tdx_config.socket_path)?;
    
    Ok(ProveData {
        proof,
        quote,
        address,
        instance_hash: pi_hash,
    })
}

pub struct ProveAggregationData {
    pub aggregation_hash: B256,
    pub proof: Vec<u8>,
    pub quote: TdxQuote,
    pub new_instance: Address,
}

pub fn prove_aggregation(
    input: &AggregationGuestInput,
    tdx_config: &TdxConfig,
) -> Result<ProveAggregationData> {
    let instance_id = load_instance_id().unwrap_or(tdx_config.instance_id);
    let private_key = load_private_key()?;
    let new_instance = get_address_from_private_key(&private_key)?;

    let raw_input = RawAggregationGuestInput {
        proofs: input
            .proofs
            .iter()
            .map(|proof| {
                let proof_data: TdxProverData = serde_json::from_str(&proof.proof.as_ref().unwrap())
                    .map_err(|e| anyhow!("Failed to parse TDX proof data: {}", e))?;
                
                Ok(raiko_lib::input::RawProof {
                    input: proof.input.unwrap(),
                    proof: hex::decode(&proof_data.proof[2..])?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    };

    let old_instance = if !raw_input.proofs.is_empty() {
        Address::from_slice(&raw_input.proofs[0].proof[4..24])
    } else {
        new_instance
    };
    
    let mut cur_instance = old_instance;
    for proof in raw_input.proofs.iter() {
        let signature = &proof.proof[24..89];
        let signature_array: [u8; 65] = signature.try_into()
            .map_err(|e: core::array::TryFromSliceError| anyhow!("Invalid signature length: {}", e))?;
        let recovered = recover_signer_unchecked(&signature_array, &proof.input)?;
        
        if recovered != cur_instance {
            return Err(anyhow!("Proof chain verification failed: expected signer {}, got {}", cur_instance, recovered));
        }
        
        cur_instance = Address::from_slice(&proof.proof[4..24]);
    }
    
    if cur_instance != new_instance {
        return Err(anyhow!("Proof chain does not end with current instance: expected {}, got {}", new_instance, cur_instance));
    }
    
    let aggregation_hash: B256 = B256::from(keccak(aggregation_output_combine(
        [
            vec![
                B256::left_padding_from(old_instance.as_ref()),
                B256::left_padding_from(new_instance.as_ref()),
            ],
            raw_input.proofs.iter().map(|proof| proof.input).collect::<Vec<_>>(),
        ]
        .concat(),
    )));
    
    let signature = sign_message(&private_key, &aggregation_hash)?;
    let proof = create_aggregation_proof(instance_id, &old_instance, &new_instance, &signature)?;
    let quote = generate_tdx_quote(&aggregation_hash, &tdx_config.socket_path)?;
    
    Ok(ProveAggregationData {
        aggregation_hash,
        proof,
        quote,
        new_instance,
    })
}
