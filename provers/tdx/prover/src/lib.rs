#![cfg(feature = "enable")]

use anyhow::Result;
use raiko_lib::{
    input::{AggregationGuestInput, AggregationGuestOutput, GuestBatchInput, GuestInput, GuestBatchOutput, GuestOutput},
    proof_type::ProofType,
    prover::{IdStore, IdWrite, Proof, ProofKey, Prover, ProverConfig, ProverError, ProverResult},
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tracing::info;

mod attestation_client;
mod config;
mod proof;
mod signature;

pub const TDX_PROVER_CODE: u8 = ProofType::Tdx as u8;
pub const TDX_PROOF_SIZE: usize = 89;
pub const TDX_AGGREGATION_PROOF_SIZE: usize = 109;

pub struct TdxProver;

#[serde_as]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TdxConfig {
    pub instance_id: u32,
    pub socket_path: String,
    pub bootstrap: bool,
    pub prove: bool,
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
            let quote_data = TdxProver::bootstrap(&config).await.map_err(|e| ProverError::GuestError(e.to_string()))?;
            quote = Some(hex::encode(&quote_data));
        }

        if tdx_config.prove {
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
            let quote_data = TdxProver::bootstrap(&config).await.map_err(|e| ProverError::GuestError(e.to_string()))?;
            quote = Some(hex::encode(&quote_data));
        }

        if tdx_config.prove {
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
            let quote_data = TdxProver::bootstrap(&config).await.map_err(|e| ProverError::GuestError(e.to_string()))?;
            quote = Some(hex::encode(&quote_data));
        }

        if tdx_config.prove {
            let aggregation_data = proof::prove_aggregation(&input, &tdx_config)
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

    async fn cancel(&self, _proof_key: ProofKey, _store: Box<&mut dyn IdStore>) -> ProverResult<()> {
        Ok(())
    }
}

impl TdxProver {
    pub async fn bootstrap(config: &serde_json::Value) -> Result<Vec<u8>> {
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
        info!("TDX quote generated (length: {} bytes)", quote.len());

        Ok(quote)
    }

    pub async fn set_instance_id(instance_id: u32) -> Result<()> {
        info!("Setting instance ID: {}", instance_id);

        config::set_instance_id(instance_id)?;

        info!("Instance ID set to: {}", instance_id);
        Ok(())
    }
}
