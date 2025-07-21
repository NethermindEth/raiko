use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use hex::ToHex;
use raiko_core::{
    interfaces::{
        AggregationGuestInput, AggregationGuestOutput, ProofRequestOpt, ProverGuestInput,
        ProverGuestOutput, RaikoProof, RaikoProverData,
    },
    Prover,
};
use raiko_lib::prover::{IdStore, ProofKey, ProverError};
use raiko_lib::{
    primitives::{Address, B256},
    proof_type::ProofType,
    Measurement,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use tokio::process::Command;
use tracing::{debug, error, info, warn};

pub const TDX_PROVER_CODE: u8 = ProofType::Tdx as u8;
pub const TDX_PROOF_SIZE: usize = 89;

pub struct TdxProver;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TdxConfig {
    pub config_dir: PathBuf,
    pub instance_id: u32,
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
        input: ProverGuestInput,
        output: &ProverGuestOutput,
        _config: &ProofRequestOpt,
    ) -> Result<RaikoProof> {
        info!("Running TDX prover");

        let config_dir = get_config_dir()?;

        let private_key = load_private_key(&config_dir)?;
        let public_key = get_public_key_from_private(&private_key)?;

        let instance_id = load_instance_id(&config_dir)?;

        let pi_hash = output.protocol_instance.sgx_instance(instance_id).calc_hash();
        let signature = sign_message(&private_key, &pi_hash)?;
        let proof = create_proof(instance_id, &public_key, &signature)?;
        let quote = generate_tdx_quote(&pi_hash)?;

        let prover_data = TdxProverData {
            proof: hex::encode(&proof),
            quote: hex::encode(&quote.data),
            public_key: public_key.encode_hex(),
        };
        
        Ok(RaikoProof {
            proof: serde_json::to_string(&prover_data)?,
            proof_type: TDX_PROVER_CODE,
        })
    }

    async fn aggregate(
        _inputs: Vec<AggregationGuestInput>,
        _output: &AggregationGuestOutput,
        _config: &ProofRequestOpt,
    ) -> Result<RaikoProof> {
        bail!("TDX prover doesn't support aggregation")
    }

    async fn cancel(_proof_key: ProofKey, _read: Box<&mut dyn IdStore>) -> Result<()> {
        Ok(())
    }
}

impl TdxProver {
    pub async fn bootstrap(config_dir: &Path) -> Result<()> {
        info!("Bootstrapping TDX prover");
        
        fs::create_dir_all(config_dir)?;
        
        let private_key = generate_private_key()?;
        save_private_key(config_dir, &private_key)?;
        
        let public_key = get_public_key_from_private(&private_key)?;
        info!("Generated public key: {}", public_key.encode_hex());
        
        let bootstrap_data = public_key.to_vec();
        let quote = generate_tdx_quote(&B256::from_slice(&bootstrap_data[..32]))?;
        
        info!("Bootstrap complete. Public key address: {}", public_key.encode_hex());
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
    signature[64] = recovery_id.to_i32() as u8;
    
    Ok(signature)
}

fn create_proof(instance_id: u32, public_key: &Address, signature: &[u8; 65]) -> Result<Vec<u8>> {
    let mut proof = Vec::with_capacity(TDX_PROOF_SIZE);
    
    proof.extend_from_slice(&instance_id.to_be_bytes());
    proof.extend_from_slice(public_key.as_slice());
    proof.extend_from_slice(signature);
    
    Ok(proof)
}

fn generate_tdx_quote(user_report_data: &B256) -> Result<TdxQuote> {
    warn!("TDX quote generation not implemented yet, returning placeholder");
    let placeholder_quote = TdxQuote {
        data: vec![0u8; 1024],
    };
    Ok(placeholder_quote)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn test_bootstrap() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config_dir = temp_dir.path();
        
        TdxProver::bootstrap(config_dir).await?;
        
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