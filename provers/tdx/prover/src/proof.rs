use anyhow::{anyhow, Result};
use raiko_lib::{
    input::{AggregationGuestInput, GuestBatchInput, GuestInput, RawAggregationGuestInput},
    primitives::{keccak::keccak, Address, B256},
    proof_type::ProofType,
    protocol_instance::{aggregation_output_combine, ProtocolInstance},
};
use rand::Rng;
use tracing::info;

use crate::{
    attestation_client,
    config::load_private_key,
    signature::{get_address_from_private_key, recover_signer_unchecked, sign_message},
    TdxConfig, TDX_AGGREGATION_PROOF_SIZE, TDX_PROOF_SIZE,
};

pub struct TdxProof {
    data: [u8; TDX_PROOF_SIZE],
}

impl TdxProof {
    pub fn new(instance_id: u32, public_key: &Address, signature: &[u8; 65]) -> Self {
        let mut data = [0u8; TDX_PROOF_SIZE];
        data[0..4].copy_from_slice(&instance_id.to_be_bytes());
        data[4..24].copy_from_slice(public_key.as_slice());
        data[24..89].copy_from_slice(signature);
        Self { data }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != TDX_PROOF_SIZE {
            return Err(anyhow!(
                "Invalid proof size: expected {}, got {}",
                TDX_PROOF_SIZE,
                bytes.len()
            ));
        }
        let mut data = [0u8; TDX_PROOF_SIZE];
        data.copy_from_slice(bytes);
        Ok(Self { data })
    }

    pub fn instance_id(&self) -> u32 {
        u32::from_be_bytes(self.data[0..4].try_into().unwrap())
    }

    pub fn public_key(&self) -> Address {
        Address::from_slice(&self.data[4..24])
    }

    pub fn signature(&self) -> [u8; 65] {
        self.data[24..89].try_into().unwrap()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn to_vec(self) -> Vec<u8> {
        self.data.to_vec()
    }
}

pub struct TdxAggregationProof {
    data: [u8; TDX_AGGREGATION_PROOF_SIZE],
}

impl TdxAggregationProof {
    pub fn new(
        instance_id: u32,
        old_instance: &Address,
        new_instance: &Address,
        signature: &[u8; 65],
    ) -> Self {
        let mut data = [0u8; TDX_AGGREGATION_PROOF_SIZE];
        data[0..4].copy_from_slice(&instance_id.to_be_bytes());
        data[4..24].copy_from_slice(old_instance.as_slice());
        data[24..44].copy_from_slice(new_instance.as_slice());
        data[44..109].copy_from_slice(signature);
        Self { data }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != TDX_AGGREGATION_PROOF_SIZE {
            return Err(anyhow!(
                "Invalid aggregation proof size: expected {}, got {}",
                TDX_AGGREGATION_PROOF_SIZE,
                bytes.len()
            ));
        }
        let mut data = [0u8; TDX_AGGREGATION_PROOF_SIZE];
        data.copy_from_slice(bytes);
        Ok(Self { data })
    }

    pub fn instance_id(&self) -> u32 {
        u32::from_be_bytes(self.data[0..4].try_into().unwrap())
    }

    pub fn old_instance(&self) -> Address {
        Address::from_slice(&self.data[4..24])
    }

    pub fn new_instance(&self) -> Address {
        Address::from_slice(&self.data[24..44])
    }

    pub fn signature(&self) -> [u8; 65] {
        self.data[44..109].try_into().unwrap()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn to_vec(self) -> Vec<u8> {
        self.data.to_vec()
    }
}

pub fn generate_tdx_quote(user_report_data: &B256, socket_path: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    let user_data = user_report_data.as_slice();
    let nonce: [u8; 32] = rand::thread_rng().gen();
    let nonce = nonce.to_vec();

    info!("Using external attestation service at: {}", socket_path);

    let attestation_doc = attestation_client::issue_attestation(socket_path, user_data, &nonce)?;

    Ok((attestation_doc, nonce))
}

pub fn generate_tdx_quote_from_public_key(
    public_key: &Address,
    socket_path: &str,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let bootstrap_data = public_key.to_vec();
    let mut padded_data = [0u8; 32];
    padded_data[..bootstrap_data.len().min(32)]
        .copy_from_slice(&bootstrap_data[..bootstrap_data.len().min(32)]);

    generate_tdx_quote(&B256::from_slice(&padded_data), socket_path)
}

pub struct ProveData {
    pub proof: Vec<u8>,
    pub quote: Vec<u8>,
    pub nonce: Vec<u8>,
    pub address: Address,
    pub instance_hash: B256,
}

pub fn prove(input: &GuestInput, tdx_config: &TdxConfig) -> Result<ProveData> {
    let private_key = load_private_key()?;
    let address = get_address_from_private_key(&private_key)?;
    let instance_id = get_instance_id_from_params(input, tdx_config)?;

    let pi =
        ProtocolInstance::new(&input, &input.block.header, ProofType::Tdx)?.sgx_instance(address);

    let pi_hash = pi.instance_hash();
    let signature = sign_message(&private_key, &pi_hash)?;
    let proof = TdxProof::new(instance_id, &address, &signature).to_vec();
    let (quote, nonce) = generate_tdx_quote(&pi_hash, &tdx_config.socket_path)?;

    Ok(ProveData {
        proof,
        quote,
        nonce,
        address,
        instance_hash: pi_hash,
    })
}

pub struct ProveBatchData {
    pub proof: Vec<u8>,
    pub quote: Vec<u8>,
    pub nonce: Vec<u8>,
    pub address: Address,
    pub instance_hash: B256,
}

pub fn prove_batch(input: &GuestBatchInput, tdx_config: &TdxConfig) -> Result<ProveBatchData> {
    let private_key = load_private_key()?;
    let address = get_address_from_private_key(&private_key)?;
    let instance_id = get_instance_id_from_params(&input.inputs[0], tdx_config)?;

    let blocks = input
        .inputs
        .iter()
        .map(|input| input.block.clone())
        .collect::<Vec<_>>();
    let pi = ProtocolInstance::new_batch(&input, blocks, ProofType::Tdx)?.sgx_instance(address);

    let pi_hash = pi.instance_hash();
    let signature = sign_message(&private_key, &pi_hash)?;
    let proof = TdxProof::new(instance_id, &address, &signature).to_vec();
    let (quote, nonce) = generate_tdx_quote(&pi_hash, &tdx_config.socket_path)?;

    Ok(ProveBatchData {
        proof,
        quote,
        nonce,
        address,
        instance_hash: pi_hash,
    })
}

pub struct ProveAggregationData {
    pub aggregation_hash: B256,
    pub proof: Vec<u8>,
    pub quote: Vec<u8>,
    pub nonce: Vec<u8>,
    pub new_instance: Address,
}

pub fn prove_aggregation(
    input: &AggregationGuestInput,
    tdx_config: &TdxConfig,
) -> Result<ProveAggregationData> {
    let private_key = load_private_key()?;
    let new_instance = get_address_from_private_key(&private_key)?;

    let raw_input = RawAggregationGuestInput {
        proofs: input
            .proofs
            .iter()
            .map(|proof| {
                Ok(raiko_lib::input::RawProof {
                    input: proof.clone().input.unwrap(),
                    proof: hex::decode(&proof.clone().proof.unwrap().trim_start_matches("0x")).unwrap(),
                })
            })
            .collect::<Result<Vec<_>>>()?,
    };

    let first_proof = TdxProof::from_bytes(&raw_input.proofs[0].proof)?;
    let instance_id = first_proof.instance_id();
    let old_instance = first_proof.public_key();

    let mut cur_instance = old_instance;
    for proof in raw_input.proofs.iter() {
        let tdx_proof = TdxProof::from_bytes(&proof.proof)?;
        let signature = tdx_proof.signature();
        let recovered = recover_signer_unchecked(&signature, &proof.input)?;

        if recovered != cur_instance {
            return Err(anyhow!(
                "Proof chain verification failed: expected signer {}, got {}",
                cur_instance,
                recovered
            ));
        }

        cur_instance = tdx_proof.public_key();
    }

    if cur_instance != new_instance {
        return Err(anyhow!(
            "Proof chain does not end with current instance: expected {}, got {}",
            new_instance,
            cur_instance
        ));
    }

    let aggregation_hash: B256 = B256::from(keccak(aggregation_output_combine(
        [
            vec![
                B256::left_padding_from(old_instance.as_ref()),
                B256::left_padding_from(new_instance.as_ref()),
            ],
            raw_input
                .proofs
                .iter()
                .map(|proof| proof.input)
                .collect::<Vec<_>>(),
        ]
        .concat(),
    )));

    let signature = sign_message(&private_key, &aggregation_hash)?;
    let proof = TdxAggregationProof::new(instance_id, &old_instance, &new_instance, &signature).to_vec();
    let (quote, nonce) = generate_tdx_quote(&aggregation_hash, &tdx_config.socket_path)?;

    Ok(ProveAggregationData {
        aggregation_hash,
        proof,
        quote,
        nonce,
        new_instance,
    })
}

fn get_instance_id_from_params(input: &GuestInput, tdx_config: &TdxConfig) -> Result<u32> {
    let spec_id = input
        .chain_spec
        .active_fork(input.block.number, input.block.timestamp)
        .map_err(|e| anyhow!(e.to_string()))?;
    tdx_config
        .instance_ids
        .get(&spec_id)
        .cloned()
        .ok_or_else(|| anyhow!("No instance id found for spec id: {:?}", spec_id))
}
