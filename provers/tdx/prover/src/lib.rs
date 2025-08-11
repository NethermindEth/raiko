#![cfg(feature = "enable")]

use std::{fs, path::Path};

use anyhow::Result;
use raiko_lib::{
    input::{AggregationGuestInput, AggregationGuestOutput, GuestInput, GuestOutput},
    proof_type::ProofType,
    prover::{IdStore, IdWrite, Proof, ProofKey, Prover, ProverError, ProverResult},
};
use serde::{Deserialize, Serialize};
use tracing::info;

mod attestation_client;
mod config;
mod proof;
mod signature;

pub const TDX_PROVER_CODE: u8 = ProofType::Tdx as u8;
pub const TDX_PROOF_SIZE: usize = 89;
pub const TDX_AGGREGATION_PROOF_SIZE: usize = 109;

pub struct TdxProver;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TdxConfig {
    pub instance_id: u32,
    pub socket_path: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TdxQuote {
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

        let tdx_config =
            config::get_tdx_config(config).map_err(|e| ProverError::GuestError(e.to_string()))?;

        let prove_data = proof::prove(&input, &tdx_config)
            .map_err(|e| ProverError::GuestError(e.to_string()))?;

        let prover_data = TdxProverData {
            proof: hex::encode(&prove_data.proof),
            quote: hex::encode(&prove_data.quote.data),
            public_key: hex::encode(prove_data.address),
        };

        Ok(Proof {
            proof: Some(prover_data.proof),
            input: Some(prove_data.instance_hash),
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
        info!(
            "Running TDX aggregation prover for {} proofs",
            input.proofs.len()
        );

        let tdx_config =
            config::get_tdx_config(config).map_err(|e| ProverError::GuestError(e.to_string()))?;

        let aggregation_data = proof::prove_aggregation(&input, &tdx_config)
            .map_err(|e| ProverError::GuestError(e.to_string()))?;

        let prover_data = TdxProverData {
            proof: hex::encode(&aggregation_data.proof),
            quote: hex::encode(&aggregation_data.quote.data),
            public_key: hex::encode(aggregation_data.new_instance),
        };

        Ok(Proof {
            proof: Some(prover_data.proof),
            input: Some(aggregation_data.aggregation_hash),
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
    pub async fn bootstrap(config: &serde_json::Value) -> Result<()> {
        info!("Bootstrapping TDX prover");

        let tdx_config = config::get_tdx_config(config)?;
        let private_key = config::generate_private_key()?;

        let public_key = signature::get_address_from_private_key(&private_key)?;
        info!("Generated public key: {}", hex::encode(public_key));

        let quote =
            proof::generate_tdx_quote_from_public_key(&public_key, &tdx_config.socket_path)?;
        info!(
            "Bootstrap complete. Public key address: {}",
            hex::encode(public_key)
        );
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
