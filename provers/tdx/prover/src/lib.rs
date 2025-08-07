#![cfg(feature = "enable")]

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use raiko_lib::{
    input::{AggregationGuestInput, AggregationGuestOutput, GuestInput, GuestOutput, RawAggregationGuestInput},
    primitives::{Address, B256, keccak::keccak},
    proof_type::ProofType,
    protocol_instance::{aggregation_output_combine, ProtocolInstance},
    prover::{IdStore, IdWrite, Proof, ProofKey, Prover, ProverError, ProverResult},
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use tracing::{info, warn};

mod attestation_client;

// Helper to convert anyhow errors to ProverError
fn to_prover_error<T>(result: anyhow::Result<T>) -> Result<T, ProverError> {
    result.map_err(|e| ProverError::GuestError(e.to_string()))
}

pub const TDX_PROVER_CODE: u8 = ProofType::Tdx as u8;
pub const TDX_PROOF_SIZE: usize = 89;
pub const TDX_AGGREGATION_PROOF_SIZE: usize = 109;

pub struct TdxProver;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TdxConfig {
    pub config_dir: PathBuf,
    pub instance_id: u32,
    pub socket_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TdxQuote {
    // TODO: Implement actual TDX quote structure
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TdxProverData {
    pub proof: String,
    pub quote: String,
    pub public_key: String,
}

impl Prover for TdxProver {
    async fn run(
        input: GuestInput,
        _output: &GuestOutput,
        config: &serde_json::Value,
        _store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        info!("Running TDX prover");

        let config_dir = get_config_dir().map_err(|e| ProverError::GuestError(e.to_string()))?;

        let tdx_config = if let Some(tdx_section) = config.get("tdx") {
            TdxConfig::deserialize(tdx_section)
                .map_err(|e| ProverError::GuestError(format!("Failed to parse TDX config: {}", e)))?
        } else {
            return Err(ProverError::GuestError("TDX configuration not found in config".to_string()));
        };

        let private_key = to_prover_error(load_private_key(&config_dir))?;
        let public_key = to_prover_error(get_public_key_from_private(&private_key))?;
        let new_instance = public_key;

        let instance_id = load_instance_id(&config_dir)
            .unwrap_or(tdx_config.instance_id);

        let pi = to_prover_error(ProtocolInstance::new(&input, &input.block.header, ProofType::Tdx))?.sgx_instance(new_instance);
        let pi_hash = pi.instance_hash();
        let signature = to_prover_error(sign_message(&private_key, &pi_hash))?;
        let proof = to_prover_error(create_proof(instance_id, &public_key, &signature))?;
        let quote = to_prover_error(generate_tdx_quote(&pi_hash, &tdx_config.socket_path))?;

        let prover_data = TdxProverData {
            proof: hex::encode(&proof),
            quote: hex::encode(&quote.data),
            public_key: hex::encode(public_key),
        };
        
        Ok(Proof {
            proof: Some(prover_data.proof),
            input: Some(pi_hash),
            quote: Some(prover_data.quote),
            uuid: None,
            kzg_proof: None,
        })
    }

    async fn aggregate(
        input: AggregationGuestInput,
        _output: &AggregationGuestOutput,
        config: &serde_json::Value,
        _store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        info!("Running TDX aggregation prover for {} proofs", input.proofs.len());

        let config_dir = get_config_dir().map_err(|e| ProverError::GuestError(e.to_string()))?;

        let tdx_config = if let Some(tdx_section) = config.get("tdx") {
            TdxConfig::deserialize(tdx_section)
                .map_err(|e| ProverError::GuestError(format!("Failed to parse TDX config: {}", e)))?
        } else {
            return Err(ProverError::GuestError("TDX configuration not found in config".to_string()));
        };

        let private_key = to_prover_error(load_private_key(&config_dir))?;
        let new_instance = to_prover_error(get_public_key_from_private(&private_key))?;

        let instance_id = load_instance_id(&config_dir)
            .unwrap_or(tdx_config.instance_id);

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
                .collect::<Result<Vec<_>>>().map_err(|e| ProverError::GuestError(e.to_string()))?,
        };

        let old_instance = if !raw_input.proofs.is_empty() {
            Address::from_slice(&raw_input.proofs[0].proof[4..24])
        } else {
            new_instance
        };
        
        let mut cur_instance = old_instance;

        for proof in raw_input.proofs.iter() {
            let signature = &proof.proof[24..89];
            let signature_array: [u8; 65] = signature.try_into().map_err(|e: core::array::TryFromSliceError| ProverError::GuestError(format!("Invalid signature length: {}", e)))?;
            let recovered = to_prover_error(recover_signer_unchecked(&signature_array, &proof.input))?;
            
            if recovered != cur_instance {
                return Err(ProverError::GuestError(format!("Proof chain verification failed: expected signer {}, got {}", cur_instance, recovered)));
            }

            cur_instance = Address::from_slice(&proof.proof[4..24]);
        }

        if cur_instance != new_instance {
            return Err(ProverError::GuestError(format!("Proof chain does not end with current instance: expected {}, got {}", new_instance, cur_instance)));
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

        let signature = to_prover_error(sign_message(&private_key, &aggregation_hash))?;

        let proof = to_prover_error(create_aggregation_proof(instance_id, &old_instance, &new_instance, &signature))?;

        let quote = to_prover_error(generate_tdx_quote(&aggregation_hash, &tdx_config.socket_path))?;

        let prover_data = TdxProverData {
            proof: hex::encode(&proof),
            quote: hex::encode(&quote.data),
            public_key: hex::encode(new_instance),
        };

        Ok(Proof {
            proof: Some(prover_data.proof),
            input: Some(aggregation_hash),
            quote: Some(prover_data.quote),
            uuid: None,
            kzg_proof: None,
        })
    }

    async fn cancel(_proof_key: ProofKey, _store: Box<&mut dyn IdStore>) -> ProverResult<()> {
        Ok(())
    }
}

impl TdxProver {
    pub async fn bootstrap(config_dir: &Path, socket_path: &str) -> Result<()> {
        info!("Bootstrapping TDX prover");
        
        fs::create_dir_all(config_dir)?;
        
        let private_key = generate_private_key()?;
        save_private_key(config_dir, &private_key)?;
        
        let public_key = get_public_key_from_private(&private_key)?;
        info!("Generated public key: {}", hex::encode(public_key));
        
        let bootstrap_data = public_key.to_vec();
        let mut padded_data = [0u8; 32];
        padded_data[..bootstrap_data.len().min(32)].copy_from_slice(&bootstrap_data[..bootstrap_data.len().min(32)]);
        let quote = generate_tdx_quote(&B256::from_slice(&padded_data), socket_path)?;
        info!("Bootstrap complete. Public key address: {}", hex::encode(public_key));
        info!("TDX quote generated (length: {} bytes)", quote.data.len());
        
        Ok(())
    }
    
    pub async fn set_instance_id(config_dir: &Path, instance_id: u32) -> Result<()> {
        info!("Setting instance ID: {}", instance_id);
        
        let instance_file = config_dir.join("instance_id");
        fs::write(&instance_file, instance_id.to_string())?;
        
        info!("Instance ID saved to: {}", instance_file.display());
        Ok(())
    }
}

// Helper functions

pub fn get_config_dir() -> Result<PathBuf> {
    let home_dir = dirs::home_dir().ok_or_else(|| anyhow!("Failed to get home directory"))?;
    Ok(home_dir.join(".config").join("raiko").join("tdx"))
}

fn generate_private_key() -> Result<secp256k1::SecretKey> {
    let secp = secp256k1::Secp256k1::new();
    let (secret_key, _) = secp.generate_keypair(&mut secp256k1::rand::thread_rng());
    Ok(secret_key)
}

fn save_private_key(config_dir: &Path, private_key: &secp256k1::SecretKey) -> Result<()> {
    let secrets_dir = config_dir.join("secrets");
    fs::create_dir_all(&secrets_dir)?;
    
    let key_file = secrets_dir.join("priv.key");
    fs::write(&key_file, private_key.secret_bytes())?;
    
    // Set file permissions to 0600 (read/write for owner only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&key_file)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&key_file, perms)?;
    }
    
    Ok(())
}

pub fn load_private_key(config_dir: &Path) -> Result<secp256k1::SecretKey> {
    let key_file = config_dir.join("secrets").join("priv.key");
    let key_bytes = fs::read(&key_file)
        .with_context(|| format!("Failed to read private key from {}", key_file.display()))?;
    
    secp256k1::SecretKey::from_slice(&key_bytes)
        .map_err(|e| anyhow!("Invalid private key: {}", e))
}

pub fn get_public_key_from_private(private_key: &secp256k1::SecretKey) -> Result<Address> {
    let secp = secp256k1::Secp256k1::new();
    let public_key = secp256k1::PublicKey::from_secret_key(&secp, private_key);
    
    // Convert public key to Ethereum address
    let public_key_bytes = public_key.serialize_uncompressed();
    let hash = Keccak256::digest(&public_key_bytes[1..]); // Skip the 0x04 prefix
    
    Ok(Address::from_slice(&hash[12..]))
}

fn load_instance_id(config_dir: &Path) -> Result<u32> {
    let instance_file = config_dir.join("instance_id");
    let instance_str = fs::read_to_string(&instance_file)
        .with_context(|| format!("Failed to read instance ID from {}", instance_file.display()))?;
    
    instance_str.trim().parse::<u32>()
        .map_err(|e| anyhow!("Invalid instance ID: {}", e))
}

fn sign_message(private_key: &secp256k1::SecretKey, message: &B256) -> Result<[u8; 65]> {
    let secp = secp256k1::Secp256k1::new();
    let message = secp256k1::Message::from_digest_slice(message.as_slice())?;
    let sig = secp.sign_ecdsa_recoverable(&message, private_key);
    
    let (recovery_id, sig_bytes) = sig.serialize_compact();
    let mut signature = [0u8; 65];
    signature[..64].copy_from_slice(&sig_bytes);
    signature[64] = recovery_id.to_i32() as u8 + 27; // Add 27 for Ethereum compatibility
    
    Ok(signature)
}

fn recover_signer_unchecked(sig: &[u8; 65], msg: &B256) -> Result<Address> {
    use secp256k1::{ecdsa::{RecoverableSignature, RecoveryId}, Message};
    
    let sig = RecoverableSignature::from_compact(
        &sig[0..64],
        RecoveryId::from_i32((sig[64] as i32) - 27)?,
    )?;
    
    let secp = secp256k1::Secp256k1::new();
    let message = Message::from_digest_slice(msg.as_slice())?;
    let public_key = secp.recover_ecdsa(&message, &sig)?;
    
    // Convert public key to Ethereum address
    let public_key_bytes = public_key.serialize_uncompressed();
    let hash = Keccak256::digest(&public_key_bytes[1..]); // Skip the 0x04 prefix
    
    Ok(Address::from_slice(&hash[12..]))
}

fn create_proof(instance_id: u32, public_key: &Address, signature: &[u8; 65]) -> Result<Vec<u8>> {
    let mut proof = Vec::with_capacity(TDX_PROOF_SIZE);
    
    proof.extend_from_slice(&instance_id.to_be_bytes());
    proof.extend_from_slice(public_key.as_slice());
    proof.extend_from_slice(signature);
    
    Ok(proof)
}

fn create_aggregation_proof(
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

fn generate_tdx_quote(user_report_data: &B256, socket_path: &str) -> Result<TdxQuote> {
    let user_data = user_report_data.as_slice();
    let nonce: [u8; 32] = rand::thread_rng().gen();
    let nonce = nonce.to_vec();

    info!("Using external attestation service at: {}", socket_path);
    
    let attestation_doc = attestation_client::issue_attestation(socket_path, user_data, &nonce)?;

    Ok(TdxQuote {
        data: attestation_doc,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_bootstrap() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config_dir = temp_dir.path();
        
        TdxProver::bootstrap(config_dir, "/tmp/test.sock").await?;
        
        assert!(config_dir.join("secrets").join("priv.key").exists());
        
        Ok(())
    }
    
    #[tokio::test]
    async fn test_set_instance_id() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config_dir = temp_dir.path();
        
        TdxProver::set_instance_id(config_dir, 12345).await?;
        
        let saved_id = load_instance_id(config_dir)?;
        assert_eq!(saved_id, 12345);
        
        Ok(())
    }
}