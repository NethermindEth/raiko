use crate::{
    methods::risc0_guest::RISC0_GUEST_ID,
    snarks::{stark2snark, verify_groth16_from_snark_receipt},
    Risc0Response,
};
use alloy_primitives::B256;
use bonsai_sdk::blocking::{Client, SessionId};
use log::{debug, error, info, warn};
use raiko_lib::{
    primitives::keccak::keccak,
    prover::{IdWrite, ProofKey, ProverError, ProverResult},
};
use risc0_zkvm::{
    compute_image_id, is_dev_mode, serde::to_vec, sha::Digest, AssumptionReceipt, ExecutorEnv,
    Receipt,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    fmt::Debug,
    fs,
    path::{Path, PathBuf},
};
use tokio::time::{sleep as tokio_async_sleep, Duration};

use crate::Risc0Param;

const MAX_REQUEST_RETRY: usize = 8;

#[derive(thiserror::Error, Debug)]
pub enum BonsaiExecutionError {
    // common errors: include sdk error, or some others from non-bonsai code
    #[error(transparent)]
    SdkFailure(#[from] bonsai_sdk::SdkErr),
    #[error("bonsai execution error: {0}")]
    Other(String),
    // critical error like OOM, which is un-recoverable
    #[error("bonsai execution fatal error: {0}")]
    Fatal(String),
}

#[cfg(feature = "bonsai-auto-scaling")]
pub mod auto_scaling;

pub async fn verify_bonsai_receipt<O: Eq + Debug + DeserializeOwned>(
    image_id: Digest,
    expected_output: &O,
    uuid: String,
    max_retries: usize,
) -> Result<(String, Receipt), BonsaiExecutionError> {
    info!("Tracking receipt uuid: {uuid}");
    let session = SessionId { uuid };

    loop {
        let mut res = None;
        for attempt in 1..=max_retries {
            let client = Client::from_env(risc0_zkvm::VERSION)?;

            match session.status(&client) {
                Ok(response) => {
                    res = Some(response);
                    break;
                }
                Err(err) => {
                    if attempt == max_retries {
                        return Err(BonsaiExecutionError::SdkFailure(err));
                    }
                    warn!("Attempt {attempt}/{max_retries} for session status request: {err:?}");
                    tokio_async_sleep(Duration::from_secs(15)).await;
                    continue;
                }
            }
        }

        let res =
            res.ok_or_else(|| BonsaiExecutionError::Other("status result not found!".to_owned()))?;

        if res.status == "RUNNING" {
            info!(
                "Current  {session:?} status: {} - state: {} - continue polling...",
                res.status,
                res.state.unwrap_or_default()
            );
            tokio_async_sleep(Duration::from_secs(15)).await;
        } else if res.status == "SUCCEEDED" {
            // Download the receipt, containing the output
            info!("Prove task {session:?} success.");
            let receipt_url = res
                .receipt_url
                .expect("API error, missing receipt on completed session");
            let client = Client::from_env(risc0_zkvm::VERSION)?;
            let receipt_buf = client.download(&receipt_url)?;
            let receipt: Receipt = bincode::deserialize(&receipt_buf).map_err(|e| {
                BonsaiExecutionError::Other(format!("Failed to deserialize receipt: {e:?}"))
            })?;
            receipt
                .verify(image_id)
                .expect("Receipt verification failed");
            // verify output
            let receipt_output: O = receipt
                .journal
                .decode()
                .map_err(|e| BonsaiExecutionError::Other(e.to_string()))?;
            if expected_output == &receipt_output {
                info!("Receipt validated!");
            } else {
                error!(
                    "Output mismatch! Receipt: {receipt_output:?}, expected: {expected_output:?}",
                );
            }
            return Ok((session.uuid, receipt));
        } else {
            let client = Client::from_env(risc0_zkvm::VERSION)?;
            let bonsai_err_log = session.logs(&client);
            return Err(BonsaiExecutionError::Fatal(format!(
                "Workflow {session:?} exited: {} - | err: {} | log: {bonsai_err_log:?}",
                res.status,
                res.error_msg.unwrap_or_default(),
            )));
        }
    }
}

pub async fn maybe_prove<I: Serialize, O: Eq + Debug + Serialize + DeserializeOwned>(
    param: &Risc0Param,
    encoded_input: Vec<u32>,
    elf: &[u8],
    expected_output: &O,
    assumptions: (Vec<impl Into<AssumptionReceipt>>, Vec<String>),
    proof_key: ProofKey,
    id_store: &mut Option<&mut dyn IdWrite>,
) -> Option<(String, Receipt)> {
    let (assumption_instances, assumption_uuids) = assumptions;

    let encoded_output =
        to_vec(expected_output).expect("Could not serialize expected proving output!");
    let computed_image_id = compute_image_id(elf).expect("Failed to compute elf image id!");

    let receipt_label = format!(
        "{}-{}",
        hex::encode(computed_image_id),
        hex::encode(keccak(bytemuck::cast_slice(&encoded_output)))
    );

    // get receipt
    let (mut receipt_uuid, receipt, cached) =
        if let Ok(Some(cached_data)) = load_receipt(&receipt_label) {
            info!("Loaded locally cached stark receipt {receipt_label:?}");
            (cached_data.0, cached_data.1, true)
        } else if param.bonsai {
            #[cfg(feature = "bonsai-auto-scaling")]
            match auto_scaling::maxpower_bonsai().await {
                Ok(_) => {}
                Err(e) => {
                    error!("Failed to scale up bonsai: {e:?}");
                    return None;
                }
            }
            // query bonsai service until it works
            loop {
                match prove_bonsai(
                    encoded_input.clone(),
                    elf,
                    expected_output,
                    assumption_uuids.clone(),
                    proof_key,
                    id_store,
                )
                .await
                {
                    Ok((receipt_uuid, receipt)) => {
                        break (receipt_uuid, receipt, false);
                    }
                    Err(BonsaiExecutionError::SdkFailure(err)) => {
                        warn!("Bonsai SDK fail: {err:?}, keep tracking...");
                        tokio_async_sleep(Duration::from_secs(15)).await;
                    }
                    Err(BonsaiExecutionError::Other(err)) => {
                        warn!("Something wrong: {err:?}, keep tracking...");
                        tokio_async_sleep(Duration::from_secs(15)).await;
                    }
                    Err(BonsaiExecutionError::Fatal(err)) => {
                        error!("Fatal error on Bonsai: {err:?}");
                        return None;
                    }
                }
            }
        } else {
            // run prover
            info!("start running local prover");
            match prove_locally(
                param.execution_po2,
                encoded_input,
                elf,
                assumption_instances,
                param.profile,
            ) {
                Ok(receipt) => (Default::default(), receipt, false),
                Err(e) => {
                    warn!("Failed to prove locally: {e:?}");
                    return None;
                }
            }
        };

    debug!("receipt: {receipt:?}");
    debug!("journal: {:?}", receipt.journal);

    // verify output
    let output_guest: O = receipt.journal.decode().unwrap();
    if expected_output == &output_guest {
        info!("Prover succeeded");
    } else {
        error!("Output mismatch! Prover: {output_guest:?}, expected: {expected_output:?}");
    }

    // upload receipt to bonsai
    if param.bonsai && receipt_uuid.is_empty() {
        info!("Uploading cached receipt without UUID to Bonsai.");
        receipt_uuid = upload_receipt(&receipt)
            .await
            .expect("Failed to upload cached receipt to Bonsai");
    }

    let result = (receipt_uuid, receipt);

    // save receipt
    if !cached {
        save_receipt(&receipt_label, &result);
    }

    // return result
    Some(result)
}

pub async fn upload_receipt(receipt: &Receipt) -> anyhow::Result<String> {
    let client = Client::from_env(risc0_zkvm::VERSION)?;
    Ok(client.upload_receipt(bincode::serialize(receipt)?)?)
}

pub async fn cancel_proof(uuid: String) -> anyhow::Result<()> {
    let client = Client::from_env(risc0_zkvm::VERSION)?;
    let session = SessionId { uuid };
    session.stop(&client)?;
    #[cfg(feature = "bonsai-auto-scaling")]
    auto_scaling::shutdown_bonsai().await?;
    Ok(())
}

pub async fn prove_bonsai<O: Eq + Debug + DeserializeOwned>(
    encoded_input: Vec<u32>,
    elf: &[u8],
    expected_output: &O,
    assumption_uuids: Vec<String>,
    proof_key: ProofKey,
    id_store: &mut Option<&mut dyn IdWrite>,
) -> Result<(String, Receipt), BonsaiExecutionError> {
    info!("Proving on Bonsai");
    // Compute the image_id, then upload the ELF with the image_id as its key.
    let image_id = risc0_zkvm::compute_image_id(elf)
        .map_err(|e| BonsaiExecutionError::Other(format!("Failed to compute image id: {e:?}")))?;
    let encoded_image_id = hex::encode(image_id);
    // Prepare input data
    let input_data = bytemuck::cast_slice(&encoded_input).to_vec();

    let client = Client::from_env(risc0_zkvm::VERSION)?;
    client.upload_img(&encoded_image_id, elf.to_vec())?;
    // upload input
    let input_id = client.upload_input(input_data.clone())?;

    let session = client.create_session(
        encoded_image_id.clone(),
        input_id.clone(),
        assumption_uuids.clone(),
        false,
    )?;

    if let Some(id_store) = id_store {
        id_store
            .store_id(proof_key, session.uuid.clone())
            .await
            .map_err(|e| {
                BonsaiExecutionError::Other(format!("Failed to store session id: {e:?}"))
            })?;
    }

    verify_bonsai_receipt(
        image_id,
        expected_output,
        session.uuid.clone(),
        MAX_REQUEST_RETRY,
    )
    .await
}

pub async fn bonsai_stark_to_snark(
    stark_uuid: String,
    stark_receipt: Receipt,
    input: B256,
) -> ProverResult<Risc0Response> {
    let image_id = Digest::from(RISC0_GUEST_ID);
    let (snark_uuid, snark_receipt) = stark2snark(
        image_id,
        stark_uuid.clone(),
        stark_receipt.clone(),
        MAX_REQUEST_RETRY,
    )
    .await
    .map_err(|err| format!("Failed to convert STARK to SNARK: {err:?}"))?;

    info!("Validating SNARK uuid: {snark_uuid}");

    let enc_proof = verify_groth16_from_snark_receipt(image_id, snark_receipt)
        .await
        .map_err(|err| format!("Failed to verify SNARK: {err:?}"))?;

    let snark_proof = format!("0x{}", hex::encode(enc_proof));
    Ok(Risc0Response {
        proof: snark_proof,
        receipt: serde_json::to_string(&stark_receipt).unwrap(),
        uuid: stark_uuid,
        input,
    })
}

/// Prove the given ELF locally with the given input and assumptions. The segments are
/// stored in a temporary directory, to allow for proofs larger than the available memory.
pub fn prove_locally(
    segment_limit_po2: u32,
    encoded_input: Vec<u32>,
    elf: &[u8],
    assumptions: Vec<impl Into<AssumptionReceipt>>,
    profile: bool,
) -> ProverResult<Receipt> {
    debug!("Proving with segment_limit_po2 = {segment_limit_po2:?}");
    debug!(
        "Input size: {} words ( {} MB )",
        encoded_input.len(),
        encoded_input.len() * 4 / 1_000_000
    );

    info!("Running the prover...");
    // Build the environment
    let mut env_builder = ExecutorEnv::builder();
    env_builder
        .session_limit(None)
        .segment_limit_po2(segment_limit_po2)
        .write_slice(&encoded_input);

    if profile {
        info!("Profiling enabled.");
        env_builder.enable_profiler("profile_r0_local.pb");
    }

    for assumption in assumptions {
        env_builder.add_assumption(assumption);
    }

    let segment_dir = PathBuf::from("/tmp/risc0-cache");
    if !segment_dir.exists() {
        fs::create_dir(segment_dir.clone()).map_err(|e| ProverError::FileIo(e))?;
    }
    let env = env_builder
        .segment_path(segment_dir)
        .build()
        .map_err(|e| ProverError::GuestError(e.to_string()))?;

    // prove
    let prover = risc0_zkvm::default_prover();
    let receipt = prover
        .prove_with_opts(
            env,
            elf,
            &risc0_zkvm::ProverOpts::groth16(),
        )
        .map_err(|e| ProverError::GuestError(e.to_string()))?
        .receipt;

    Ok(receipt)
}

pub async fn locally_verify_snark(
    snark_uuid: String,
    snark_receipt: Receipt,
    input: B256,
) -> ProverResult<Risc0Response> {
    let image_id = Digest::from(RISC0_GUEST_ID);

    info!("Validating SNARK uuid: {snark_uuid}");

    let receipt = serde_json::to_string(&snark_receipt).unwrap();

    let enc_proof = verify_groth16_from_snark_receipt(image_id, snark_receipt)
        .await
        .map_err(|err| format!("Failed to verify SNARK: {err:?}"))?;

    let snark_proof = format!("0x{}", hex::encode(enc_proof));
    Ok(Risc0Response {
        proof: snark_proof,
        receipt,
        uuid: snark_uuid,
        input,
    })
}

pub fn load_receipt<T: serde::de::DeserializeOwned>(
    file_name: &String,
) -> anyhow::Result<Option<(String, T)>> {
    if is_dev_mode() {
        // Nothing to load
        return Ok(None);
    }

    let receipt_serialized = match fs::read(zkp_cache_path(file_name)) {
        Ok(receipt_serialized) => receipt_serialized,
        Err(err) => {
            debug!("Could not load cached receipt with label: {}", &file_name);
            debug!("{err:?}");
            return Ok(None);
        }
    };

    Ok(Some(bincode::deserialize(&receipt_serialized)?))
}

pub fn save_receipt<T: serde::Serialize>(receipt_label: &String, receipt_data: &(String, T)) {
    if !is_dev_mode() {
        let cache_path = zkp_cache_path(receipt_label);
        info!("Saving receipt to cache: {cache_path:?}");
        fs::write(
            cache_path,
            bincode::serialize(receipt_data).expect("Failed to serialize receipt!"),
        )
        .expect("Failed to save receipt output file.");
    }
}

fn zkp_cache_path(receipt_label: &String) -> String {
    Path::new("/tmp/risc0-cache")
        .join(format!("{receipt_label}.zkp"))
        .to_str()
        .unwrap()
        .to_string()
}