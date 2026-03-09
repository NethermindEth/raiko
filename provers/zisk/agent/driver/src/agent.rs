use once_cell::sync::Lazy;
use raiko_lib::{
    input::{
        AggregationGuestInput, AggregationGuestOutput, GuestBatchInput, GuestBatchOutput,
        GuestInput, GuestOutput, ShastaAggregationGuestInput, ShastaZiskAggregationGuestInput,
        ZkAggregationGuestInput,
    },
    prover::{Proof, ProofKey},
};
use raiko_lib::{
    libhash::hash_shasta_subproof_input,
    primitives::{Address, B256},
    proof_type::ProofType as RaikoProofType,
    prover::{IdStore, IdWrite, Prover, ProverConfig, ProverError, ProverResult},
};
use serde_json::{json, Value};
use std::path::PathBuf;
use tracing::info;

use fields::{Goldilocks, PrimeField64};
use proofman::{SnarkProof, SnarkWrapper};
use proofman_common::{ParamsGPU, VerboseMode};
use zisk_common::io::ZiskStdin;
use zisk_sdk::ProverClientBuilder;

const GUEST_ELF_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../guest/elf");

fn elf_path(elf_name: &str) -> PathBuf {
    PathBuf::from(GUEST_ELF_DIR).join(elf_name)
}

fn compute_vkey_hex(elf_name: &str) -> String {
    let config = ZiskLocalConfig::from_env();
    let path = elf_path(elf_name);

    // Run rom_full_setup if cache files don't exist yet
    ensure_rom_setup(&path, &config).expect("Failed to run rom_full_setup");

    let root =
        rom_setup::rom_vkey(&path, &None, &config.proving_key).expect("Failed to compute rom_vkey");
    let vkey_bytes: Vec<u8> = root
        .iter()
        .flat_map(|x| x.as_canonical_u64().to_le_bytes())
        .collect();
    format!("0x{}", hex::encode(vkey_bytes))
}

static BATCH_VKEY: Lazy<String> = Lazy::new(|| compute_vkey_hex("zisk-batch"));
static AGG_VKEY: Lazy<String> = Lazy::new(|| compute_vkey_hex("zisk-aggregation"));
static SHASTA_AGG_VKEY: Lazy<String> = Lazy::new(|| compute_vkey_hex("zisk-shasta-aggregation"));

// ---------------------------------------------------------------------------
// Local proving config
// ---------------------------------------------------------------------------

struct ZiskLocalConfig {
    proving_key: PathBuf,
    proving_key_snark: PathBuf,
    output_dir: PathBuf,
    zisk_path: PathBuf,
}

impl ZiskLocalConfig {
    fn from_env() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
        Self {
            proving_key: std::env::var("ZISK_PROVING_KEY")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(format!("{home}/.zisk/provingKey"))),
            proving_key_snark: std::env::var("ZISK_PROVING_KEY_SNARK")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(format!("{home}/.zisk/provingKeySnark"))),
            output_dir: std::env::var("ZISK_OUTPUT_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from("/tmp/zisk-proofs")),
            zisk_path: std::env::var("ZISK_PATH")
                .map(PathBuf::from)
                .unwrap_or_else(|_| PathBuf::from(format!("{home}/.zisk/zisk"))),
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn ensure_rom_setup(elf: &std::path::Path, config: &ZiskLocalConfig) -> ProverResult<()> {
    // Check if assembly cache files already exist
    let stem = elf.file_stem().unwrap().to_str().unwrap();
    let hash = rom_setup::get_elf_data_hash(elf)
        .map_err(|e| ProverError::GuestError(format!("Failed to compute ELF hash: {e}")))?;

    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".to_string());
    let cache_dir = PathBuf::from(format!("{home}/.zisk/cache"));
    let mt_path = cache_dir.join(format!("{stem}-{hash}-mt.bin"));

    if mt_path.exists() {
        info!("ROM setup cache exists at {:?}, skipping", mt_path);
        return Ok(());
    }

    info!(
        "Running rom_full_setup for {} (this may take a few minutes)",
        stem
    );
    rom_setup::rom_full_setup(elf, &config.proving_key, &config.zisk_path, &None, false)
        .map_err(|e| ProverError::GuestError(format!("rom_full_setup failed: {e}")))?;

    Ok(())
}

fn prove_stark(
    elf_name: &str,
    serialized_input: Vec<u8>,
    config: &ZiskLocalConfig,
) -> ProverResult<zisk_sdk::Proof> {
    let elf = elf_path(elf_name);
    info!("Using ELF at {:?}", elf);

    // Save serialized input for debugging/benchmarking
    std::fs::create_dir_all(&config.output_dir).ok();
    let input_path = config.output_dir.join(format!("{elf_name}-input.bin"));
    std::fs::write(&input_path, &serialized_input).ok();
    info!(
        "Saved {} input ({} bytes) to {:?}",
        elf_name,
        serialized_input.len(),
        input_path
    );

    // Build prover matching `cargo-zisk prove -a -y` (the known-working invocation)
    let gpu_params = ParamsGPU::new(false);

    let prover = ProverClientBuilder::new()
        .asm()
        .prove()
        .aggregation(true)
        .compressed(false)
        .rma(false)
        .proving_key_path(config.proving_key.clone())
        .elf_path(elf)
        .verbose(0)
        .shared_tables(false)
        .unlock_mapped_memory(false)
        .save_proofs(false)
        .output_dir(config.output_dir.clone())
        .verify_proofs(true)
        .minimal_memory(false)
        .gpu(gpu_params)
        .print_command_info()
        .build()
        .map_err(|e| ProverError::GuestError(format!("Failed to build zisk prover: {e}")))?;

    let stdin = ZiskStdin::from_vec(serialized_input);
    let result = prover
        .prove(stdin)
        .map_err(|e| ProverError::GuestError(format!("Zisk STARK proof failed: {e}")))?;

    Ok(result.proof)
}

fn wrap_snark(stark_proof: &[u64], config: &ZiskLocalConfig) -> ProverResult<SnarkProof> {
    let snark_wrapper: SnarkWrapper<Goldilocks> =
        SnarkWrapper::new(&config.proving_key_snark, VerboseMode::Info)
            .map_err(|e| ProverError::GuestError(format!("Failed to init SnarkWrapper: {e}")))?;

    let snark_proof = snark_wrapper
        .generate_final_snark_proof(stark_proof, &config.output_dir, false)
        .map_err(|e| ProverError::GuestError(format!("SNARK wrapping failed: {e}")))?;

    Ok(snark_proof)
}

fn stark_proof_to_raiko_proof(proof_u64: &[u64], output_hash: B256, vkey: Option<String>) -> Proof {
    let proof_bytes: &[u8] = bytemuck::cast_slice(proof_u64);
    Proof {
        proof: Some(format!("0x{}", hex::encode(proof_bytes))),
        quote: None,
        input: Some(output_hash),
        uuid: vkey,
        kzg_proof: None,
        extra_data: None,
    }
}

fn snark_proof_to_raiko_proof(
    snark: &SnarkProof,
    output_hash: B256,
    vkey: Option<String>,
) -> Proof {
    Proof {
        proof: Some(format!("0x{}", hex::encode(&snark.proof_bytes))),
        quote: Some(hex::encode(&snark.public_bytes)),
        input: Some(output_hash),
        uuid: vkey,
        kzg_proof: None,
        extra_data: None,
    }
}

fn vkey_to_image_id(vkey_hex: &str) -> [u32; 8] {
    let bytes =
        hex::decode(vkey_hex.strip_prefix("0x").unwrap_or(vkey_hex)).expect("invalid vkey hex");

    assert!(
        bytes.len() == 32,
        "Expected 32 bytes for vkey, got {}",
        bytes.len()
    );
    let mut image_id = [0u32; 8];

    for (i, chunk) in bytes.chunks(4).enumerate().take(8) {
        image_id[i] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    image_id
}

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

pub struct ZiskAgentProver;

impl ZiskAgentProver {
    pub async fn run(
        &self,
        _input: GuestInput,
        _output: &GuestOutput,
        _config: &Value,
        _id_store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        unimplemented!("no block run after pacaya fork")
    }

    pub async fn batch_run(
        &self,
        input: GuestBatchInput,
        output: &GuestBatchOutput,
        _config: &Value,
        _id_store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        // Force rom_full_setup (via Lazy) before anything else
        let batch_vkey = BATCH_VKEY.clone();
        info!("Zisk local batch proof starting");

        let serialized_input = bincode::serialize(&input).map_err(|e| {
            ProverError::GuestError(format!("Failed to serialize GuestBatchInput: {e}"))
        })?;

        let output_hash = output.hash;
        let proof = tokio::task::spawn_blocking(move || {
            let config = ZiskLocalConfig::from_env();
            let zisk_proof = prove_stark("zisk-batch", serialized_input, &config)?;
            let proof_u64 = zisk_proof
                .proof
                .as_ref()
                .ok_or_else(|| ProverError::GuestError("STARK proof is None".into()))?;
            Ok::<Proof, ProverError>(stark_proof_to_raiko_proof(
                proof_u64,
                output_hash,
                Some(batch_vkey),
            ))
        })
        .await
        .map_err(|e| ProverError::GuestError(format!("spawn_blocking failed: {e}")))??;

        Ok(proof)
    }

    pub async fn aggregate(
        &self,
        input: AggregationGuestInput,
        output: &AggregationGuestOutput,
        _config: &Value,
        _id_store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        // Force rom_full_setup (via Lazy) before anything else
        let agg_vkey = AGG_VKEY.clone();
        info!("Zisk local aggregation proof starting");

        let block_inputs: Vec<B256> = input
            .proofs
            .iter()
            .enumerate()
            .map(|(i, proof)| {
                proof.input.ok_or_else(|| {
                    ProverError::GuestError(format!("Proof {} input is None for aggregation", i))
                })
            })
            .collect::<ProverResult<Vec<_>>>()?;

        let zisk_input = ZkAggregationGuestInput {
            image_id: vkey_to_image_id(&BATCH_VKEY),
            block_inputs,
        };

        let serialized_input = bincode::serialize(&zisk_input).map_err(|e| {
            ProverError::GuestError(format!("Failed to serialize aggregation input: {e}"))
        })?;

        let output_hash = output.hash;
        let proof = tokio::task::spawn_blocking(move || {
            let config = ZiskLocalConfig::from_env();
            let zisk_proof = prove_stark("zisk-aggregation", serialized_input, &config)?;
            let proof_u64 = zisk_proof
                .proof
                .as_ref()
                .ok_or_else(|| ProverError::GuestError("STARK proof is None".into()))?;
            let snark = wrap_snark(proof_u64, &config)?;
            Ok::<Proof, ProverError>(snark_proof_to_raiko_proof(
                &snark,
                output_hash,
                Some(agg_vkey),
            ))
        })
        .await
        .map_err(|e| ProverError::GuestError(format!("spawn_blocking failed: {e}")))??;

        Ok(proof)
    }

    pub async fn shasta_aggregate(
        &self,
        input: ShastaAggregationGuestInput,
        output: &AggregationGuestOutput,
        _config: &Value,
        _id_store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        // Force rom_full_setup (via Lazy) before anything else
        let shasta_vkey = SHASTA_AGG_VKEY.clone();
        info!("Zisk local shasta aggregation proof starting");

        let block_inputs: Vec<B256> = input
            .proofs
            .iter()
            .enumerate()
            .map(|(i, proof)| {
                proof.input.ok_or_else(|| {
                    ProverError::GuestError(format!(
                        "Proof {} input is None for shasta aggregation",
                        i
                    ))
                })
            })
            .collect::<ProverResult<Vec<_>>>()?;

        let proof_carry_data_vec = input
            .proofs
            .iter()
            .enumerate()
            .map(|(i, proof)| {
                proof.extra_data.clone().ok_or_else(|| {
                    ProverError::GuestError(format!("Proof {} missing shasta proof carry data", i))
                })
            })
            .collect::<ProverResult<Vec<_>>>()?;

        if block_inputs.len() != proof_carry_data_vec.len() {
            return Err(ProverError::GuestError(format!(
                "Shasta aggregation input length mismatch: {} block inputs vs {} carry records",
                block_inputs.len(),
                proof_carry_data_vec.len()
            )));
        }

        for (i, block_input) in block_inputs.iter().enumerate() {
            let expected = hash_shasta_subproof_input(&proof_carry_data_vec[i]);
            if *block_input != expected {
                return Err(ProverError::GuestError(format!(
                    "Shasta aggregation block input {} does not match proof carry data",
                    i
                )));
            }
        }

        let shasta_input = ShastaZiskAggregationGuestInput {
            image_id: vkey_to_image_id(&BATCH_VKEY),
            block_inputs,
            proof_carry_data_vec,
            prover_address: Address::ZERO,
        };

        let serialized_input = bincode::serialize(&shasta_input).map_err(|e| {
            ProverError::GuestError(format!("Failed to serialize shasta input: {e}"))
        })?;

        let output_hash = output.hash;
        let proof = tokio::task::spawn_blocking(move || {
            let config = ZiskLocalConfig::from_env();
            let zisk_proof = prove_stark("zisk-shasta-aggregation", serialized_input, &config)?;
            let proof_u64 = zisk_proof
                .proof
                .as_ref()
                .ok_or_else(|| ProverError::GuestError("STARK proof is None".into()))?;
            let snark = wrap_snark(proof_u64, &config)?;
            Ok::<Proof, ProverError>(snark_proof_to_raiko_proof(
                &snark,
                output_hash,
                Some(shasta_vkey),
            ))
        })
        .await
        .map_err(|e| ProverError::GuestError(format!("spawn_blocking failed: {e}")))??;

        Ok(proof)
    }

    pub async fn cancel(
        &self,
        _proof_key: ProofKey,
        _id_store: Box<&mut dyn IdStore>,
    ) -> ProverResult<()> {
        info!("Zisk agent cancel requested - not implemented");
        Ok(())
    }
}

impl Prover for ZiskAgentProver {
    async fn get_guest_data() -> ProverResult<serde_json::Value> {
        Ok(json!({
            "zisk": {
                "batch_vkey": *BATCH_VKEY,
                "aggregation_vkey": *AGG_VKEY,
                "shasta_aggregation_vkey": *SHASTA_AGG_VKEY,
            }
        }))
    }

    async fn run(
        &self,
        input: GuestInput,
        output: &GuestOutput,
        config: &ProverConfig,
        _store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        ZiskAgentProver::run(self, input, output, config, None)
            .await
            .map_err(Into::into)
    }

    async fn batch_run(
        &self,
        input: GuestBatchInput,
        output: &GuestBatchOutput,
        config: &ProverConfig,
        _store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        ZiskAgentProver::batch_run(self, input, output, config, None)
            .await
            .map_err(Into::into)
    }

    async fn aggregate(
        &self,
        input: AggregationGuestInput,
        output: &AggregationGuestOutput,
        config: &ProverConfig,
        _store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        ZiskAgentProver::aggregate(self, input, output, config, None)
            .await
            .map_err(Into::into)
    }

    async fn shasta_aggregate(
        &self,
        input: raiko_lib::input::ShastaAggregationGuestInput,
        output: &AggregationGuestOutput,
        config: &ProverConfig,
        _store: Option<&mut dyn IdWrite>,
    ) -> ProverResult<Proof> {
        ZiskAgentProver::shasta_aggregate(self, input, output, config, None)
            .await
            .map_err(Into::into)
    }

    async fn cancel(&self, _proof_key: ProofKey, _read: Box<&mut dyn IdStore>) -> ProverResult<()> {
        Ok(())
    }

    fn proof_type(&self) -> RaikoProofType {
        RaikoProofType::Zisk
    }
}

// ===========================================================================
// Commented out: HTTP agent client code (kept for future reuse)
// ===========================================================================

// use serde::{Deserialize, Serialize};
// use std::{sync::Arc, time::Duration};
// use tokio::sync::{RwLock, Semaphore};
// use tokio::time::sleep as tokio_async_sleep;

// #[derive(Clone, Serialize, Deserialize, Debug)]
// pub struct ZiskAgentResponse {
//     pub proof: Option<String>,
//     pub receipt: Option<String>,
//     pub input: Option<[u8; 32]>,
//     pub uuid: Option<String>,
// }

// impl From<ZiskAgentResponse> for Proof {
//     fn from(value: ZiskAgentResponse) -> Self {
//         Self {
//             proof: value.proof,
//             quote: value.receipt,
//             input: value.input.map(B256::from),
//             uuid: value.uuid,
//             kzg_proof: None,
//             extra_data: None,
//         }
//     }
// }

// #[derive(Debug, Serialize)]
// #[serde(rename_all = "PascalCase")]
// enum AgentProofType {
//     Batch,
//     Aggregate,
// }

// #[derive(Debug, Serialize)]
// struct AsyncProofRequestData {
//     prover_type: &'static str,
//     input: Vec<u8>,
//     output: Vec<u8>,
//     proof_type: AgentProofType,
//     #[serde(skip_serializing_if = "Option::is_none")]
//     config: Option<Value>,
// }

// #[derive(Debug, Deserialize)]
// struct AsyncProofResponse {
//     request_id: String,
// }

// #[derive(Debug, Deserialize)]
// struct DetailedStatusResponse {
//     status: String,
//     status_message: String,
//     proof_data: Option<Vec<u8>>,
//     error: Option<String>,
//     provider_request_id: Option<String>,
// }

// #[derive(Debug, Deserialize)]
// struct ImageInfoResponse {
//     provers: Vec<ProverImages>,
// }

// #[derive(Debug, Deserialize)]
// struct ProverImages {
//     prover_type: String,
//     batch: Option<ImageDetails>,
//     aggregation: Option<ImageDetails>,
// }

// #[derive(Debug, Deserialize)]
// struct ImageDetails {
//     uploaded: bool,
//     elf_size_bytes: usize,
// }

// fn agent_auth_error(status: reqwest::StatusCode) -> Option<String> {
//     if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
//         Some("Raiko agent rejected API key (missing or invalid). Set RAIKO_AGENT_API_KEY.".to_string())
//     } else {
//         None
//     }
// }

// pub struct ZiskProverConfig {
//     pub request_concurrency_limit: usize,
//     pub status_poll_interval_secs: u64,
//     pub max_proof_timeout_secs: u64,
//     pub max_status_retries: u32,
//     pub status_retry_delay_secs: u64,
//     pub http_connect_timeout_secs: u64,
//     pub http_timeout_secs: u64,
// }

// impl Default for ZiskProverConfig {
//     fn default() -> Self {
//         Self {
//             request_concurrency_limit: 4,
//             status_poll_interval_secs: 10,
//             max_proof_timeout_secs: 3600,
//             max_status_retries: 8,
//             status_retry_delay_secs: 10,
//             http_connect_timeout_secs: 10,
//             http_timeout_secs: 60,
//         }
//     }
// }

// impl ZiskProverConfig {
//     pub fn from_env() -> Self {
//         let defaults = Self::default();
//         Self {
//             request_concurrency_limit: std::env::var("ZISK_REQUEST_CONCURRENCY_LIMIT")
//                 .ok().and_then(|v| v.parse().ok()).unwrap_or(defaults.request_concurrency_limit),
//             status_poll_interval_secs: std::env::var("ZISK_STATUS_POLL_INTERVAL_SECS")
//                 .ok().and_then(|v| v.parse().ok()).unwrap_or(defaults.status_poll_interval_secs),
//             max_proof_timeout_secs: std::env::var("ZISK_MAX_PROOF_TIMEOUT_SECS")
//                 .ok().and_then(|v| v.parse().ok()).unwrap_or(defaults.max_proof_timeout_secs),
//             max_status_retries: std::env::var("ZISK_MAX_STATUS_RETRIES")
//                 .ok().and_then(|v| v.parse().ok()).unwrap_or(defaults.max_status_retries),
//             status_retry_delay_secs: std::env::var("ZISK_STATUS_RETRY_DELAY_SECS")
//                 .ok().and_then(|v| v.parse().ok()).unwrap_or(defaults.status_retry_delay_secs),
//             http_connect_timeout_secs: std::env::var("ZISK_HTTP_CONNECT_TIMEOUT_SECS")
//                 .ok().and_then(|v| v.parse().ok()).unwrap_or(defaults.http_connect_timeout_secs),
//             http_timeout_secs: std::env::var("ZISK_HTTP_TIMEOUT_SECS")
//                 .ok().and_then(|v| v.parse().ok()).unwrap_or(defaults.http_timeout_secs),
//         }
//     }
// }

// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
// enum AggType { Base, Shasta }

// #[derive(Debug, Clone, Copy, PartialEq, Eq)]
// enum ImageType { Batch, Aggregation(AggType) }

// #[derive(Default, Debug, Clone, Copy)]
// struct ImagesUploaded {
//     batch: bool,
//     aggregation: Option<AggType>,
// }

// struct ZiskAgentClient {
//     remote_prover_url: String,
//     api_key: Option<String>,
//     request_semaphore: Arc<Semaphore>,
//     config: ZiskProverConfig,
//     images_uploaded: Arc<RwLock<ImagesUploaded>>,
// }

// impl ZiskAgentClient {
//     fn new() -> Self {
//         let remote_prover_url = std::env::var("ZISK_AGENT_URL")
//             .or_else(|_| std::env::var("RAIKO_AGENT_URL"))
//             .unwrap_or_else(|_| "http://localhost:9999/proof".to_string());
//         let api_key = std::env::var("RAIKO_AGENT_API_KEY")
//             .ok()
//             .or_else(|| std::env::var("ZISK_AGENT_API_KEY").ok());
//         let api_key = api_key.filter(|key| !key.is_empty());
//         let config = ZiskProverConfig::from_env();
//         Self {
//             remote_prover_url,
//             api_key,
//             request_semaphore: Arc::new(Semaphore::new(config.request_concurrency_limit)),
//             config,
//             images_uploaded: Arc::new(RwLock::new(ImagesUploaded::default())),
//         }
//     }

//     fn build_http_client(&self) -> ProverResult<reqwest::Client> {
//         reqwest::Client::builder()
//             .connect_timeout(Duration::from_secs(self.config.http_connect_timeout_secs))
//             .timeout(Duration::from_secs(self.config.http_timeout_secs))
//             .build()
//             .map_err(|e| ProverError::GuestError(format!("Failed to build HTTP client: {e}")))
//     }

//     fn with_api_key(&self, builder: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
//         match self.api_key.as_deref() {
//             Some(key) if !key.is_empty() => builder.header("x-api-key", key),
//             _ => builder,
//         }
//     }

//     async fn ensure_batch_uploaded(&self) -> ProverResult<()> { todo!() }
//     async fn ensure_base_agg_uploaded(&self) -> ProverResult<()> { todo!() }
//     async fn ensure_shasta_agg_uploaded(&self) -> ProverResult<()> { todo!() }
//     async fn submit_request(&self, request: AsyncProofRequestData) -> ProverResult<String> { todo!() }
//     async fn wait_for_proof(&self, request_id: String) -> ProverResult<Vec<u8>> { todo!() }
// }
