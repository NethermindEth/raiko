#![cfg(feature = "enable")]

use anyhow::Result;
use raiko_lib::{
    consts::SpecId,
    input::{
        AggregationGuestInput, AggregationGuestOutput, GuestBatchInput, GuestBatchOutput,
        GuestInput, GuestOutput,
    },
    proof_type::ProofType,
    prover::{IdStore, IdWrite, Proof, ProofKey, Prover, ProverConfig, ProverError, ProverResult},
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use std::collections::HashMap;
use tracing::info;
use serde_json::json;

mod attestation_client;
mod config;
mod proof;
mod signature;

pub const TDX_PROVER_CODE: u8 = ProofType::Tdx as u8;
pub const TDX_PROOF_SIZE: usize = 89;
pub const TDX_AGGREGATION_PROOF_SIZE: usize = 109;

pub const TDX_SOCKET_PATH: &str = "/var/tdxs.sock";

pub struct TdxProver {
    proof_type: ProofType,
}

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TdxConfig {
    pub instance_ids: HashMap<SpecId, u32>,
    pub bootstrap: bool,
    pub prove: bool,
}

impl TdxProver {
    pub fn new(proof_type: ProofType) -> Self {
        Self { proof_type }
    }
}

impl Prover for TdxProver {
    async fn run(
        &self,
        input: GuestInput,
        _output: &GuestOutput,
        config: &ProverConfig,
        _store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        info!("Running TDX prover");

        let tdx_config =
            config::get_tdx_config(config).map_err(|e| ProverError::GuestError(e.to_string()))?;

        let mut proof = None;
        let mut quote = None;
        let mut instance_hash = None;

        if tdx_config.bootstrap {
            let quote_data = TdxProver::bootstrap()
                .await
                .map_err(|e| ProverError::GuestError(e.to_string()))?;
            quote = Some(hex::encode(&quote_data));
        }

        if tdx_config.prove {
            config::validate_issuer_type(self.proof_type)
                .map_err(|e| ProverError::GuestError(e.to_string()))?;

            let prove_data = proof::prove(&input, &tdx_config)
                .map_err(|e| ProverError::GuestError(e.to_string()))?;

            proof = Some(hex::encode(&prove_data.proof));
            quote = Some(hex::encode(&prove_data.quote));
            instance_hash = Some(prove_data.instance_hash);
        }

        Ok(Proof {
            proof,
            input: instance_hash,
            quote,
            uuid: None,
            kzg_proof: None,
        })
    }

    async fn batch_run(
        &self,
        input: GuestBatchInput,
        _output: &GuestBatchOutput,
        config: &ProverConfig,
        _id_store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        info!("Running TDX prover");

        let tdx_config =
            config::get_tdx_config(config).map_err(|e| ProverError::GuestError(e.to_string()))?;

        let mut proof = None;
        let mut quote = None;
        let mut instance_hash = None;

        if tdx_config.bootstrap {
            let quote_data = TdxProver::bootstrap()
                .await
                .map_err(|e| ProverError::GuestError(e.to_string()))?;
            quote = Some(hex::encode(&quote_data));
        }

        if tdx_config.prove {
            config::validate_issuer_type(self.proof_type)
                .map_err(|e| ProverError::GuestError(e.to_string()))?;

            let prove_data = proof::prove_batch(&input, &tdx_config)
                .map_err(|e| ProverError::GuestError(e.to_string()))?;
            proof = Some(hex::encode(&prove_data.proof));
            quote = Some(hex::encode(&prove_data.quote));
            instance_hash = Some(prove_data.instance_hash);
        }

        Ok(Proof {
            proof,
            input: instance_hash,
            quote,
            uuid: None,
            kzg_proof: None,
        })
    }

    async fn aggregate(
        &self,
        input: AggregationGuestInput,
        _output: &AggregationGuestOutput,
        config: &ProverConfig,
        _store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        info!(
            "Running TDX aggregation prover for {} proofs",
            input.proofs.len()
        );

        let tdx_config =
            config::get_tdx_config(config).map_err(|e| ProverError::GuestError(e.to_string()))?;

        let mut proof = None;
        let mut quote = None;
        let mut aggregation_hash = None;

        if tdx_config.bootstrap {
            let quote_data = TdxProver::bootstrap()
                .await
                .map_err(|e| ProverError::GuestError(e.to_string()))?;
            quote = Some(hex::encode(&quote_data));
        }

        if tdx_config.prove {
            config::validate_issuer_type(self.proof_type)
                .map_err(|e| ProverError::GuestError(e.to_string()))?;

            let aggregation_data = proof::prove_aggregation(&input)
                .map_err(|e| ProverError::GuestError(e.to_string()))?;

            proof = Some(hex::encode(&aggregation_data.proof));
            quote = Some(hex::encode(&aggregation_data.quote));
            aggregation_hash = Some(aggregation_data.aggregation_hash);
        }

        Ok(Proof {
            proof,
            input: aggregation_hash,
            quote,
            uuid: None,
            kzg_proof: None,
        })
    }

    async fn cancel(
        &self,
        _proof_key: ProofKey,
        _store: Box<&mut dyn IdStore>,
    ) -> ProverResult<()> {
        Ok(())
    }

    async fn get_guest_data() -> ProverResult<serde_json::Value> {
        get_tdx_guest_data().await.map_err(|e| ProverError::GuestError(e))
    }
}

impl TdxProver {
    pub async fn bootstrap() -> Result<Vec<u8>> {
        info!("Bootstrapping TDX prover");

        if config::bootstrap_exists()? {
            info!("Already bootstrapped, loading existing configuration");
            let bootstrap_data = config::read_bootstrap()?;
            return Ok(hex::decode(bootstrap_data.quote)?);
        }

        let private_key = config::generate_private_key()?;

        let public_key = signature::get_address_from_private_key(&private_key)?;
        info!("Generated public key: {}", hex::encode(public_key));

        let (quote, nonce) =
            proof::generate_tdx_quote_from_public_key(&public_key)?;
        info!(
            "Bootstrap complete. Public key address: {}",
            hex::encode(public_key)
        );
        info!("TDX quote generated (length: {} bytes)", quote.len());

        let metadata = proof::get_tdx_metadata()?;

        config::write_bootstrap(&metadata.issuer_type, &quote, &public_key, &nonce, metadata.metadata)?;

        Ok(quote)
    }
}

async fn get_tdx_guest_data() -> Result<serde_json::Value, String> {
    if !config::bootstrap_exists().map_err(|e| format!("Failed to check bootstrap existence: {}", e))? {
        info!("Bootstrap data not found, bootstrapping TDX prover");
        TdxProver::bootstrap()
            .await
            .map_err(|e| format!("Failed to bootstrap TDX prover: {}", e))?;
    }

    let bootstrap_data = config::read_bootstrap()
        .map_err(|e| format!("Failed to read bootstrap data for guest data: {}", e))?;

    Ok(json!({
        "issuer_type": bootstrap_data.issuer_type,
        "public_key": bootstrap_data.public_key,
        "quote": bootstrap_data.quote,
        "nonce": bootstrap_data.nonce,
        "metadata": bootstrap_data.metadata,
    }))
}
