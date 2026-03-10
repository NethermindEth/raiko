use once_cell::sync::OnceCell;
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

use zisk_common::ElfBinaryFromFile;
use zisk_sdk::{
    Asm, ProofOpts, ProverClientBuilder, ZiskProgramPK, ZiskProgramVK, ZiskProof, ZiskProveResult,
    ZiskProver,
};

const GUEST_ELF_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../guest/elf");

fn elf_path(elf_name: &str) -> PathBuf {
    PathBuf::from(GUEST_ELF_DIR).join(elf_name)
}

// ---------------------------------------------------------------------------
// Local proving config
// ---------------------------------------------------------------------------

struct ZiskLocalConfig {
    proving_key: PathBuf,
    proving_key_snark: PathBuf,
    output_dir: PathBuf,
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
        }
    }
}

// ---------------------------------------------------------------------------
// Cached prover instances
// ---------------------------------------------------------------------------
//
// Building a ZiskProver starts ASM microservices (~19s) and initializes
// proofman (~12s). Since prove() and setup() take &self, provers are
// reusable. We cache them in statics so the first proof pays the init
// cost and all subsequent proofs skip it entirely (~31s saved per proof).

static STARK_PROVER: OnceCell<ZiskProver<Asm>> = OnceCell::new();
static SNARK_PROVER: OnceCell<ZiskProver<Asm>> = OnceCell::new();

// ASM microservices use TCP ports starting from a base port (default 23115).
// Each setup() allocates 3 consecutive ports (MO, MT, RH). When two provers
// coexist, they must use different base ports to avoid conflicts.
const STARK_BASE_PORT: u16 = 23115; // default
const SNARK_BASE_PORT: u16 = 23200; // offset to avoid overlap

// Per-ELF proving key + verification key caches.
// Batch uses the STARK prover; aggregation ELFs use the SNARK prover.
static BATCH_PK: OnceCell<(ZiskProgramPK, ZiskProgramVK)> = OnceCell::new();
static AGG_PK: OnceCell<(ZiskProgramPK, ZiskProgramVK)> = OnceCell::new();
static SHASTA_AGG_PK: OnceCell<(ZiskProgramPK, ZiskProgramVK)> = OnceCell::new();

fn cached_stark_prover(config: &ZiskLocalConfig) -> ProverResult<&'static ZiskProver<Asm>> {
    STARK_PROVER.get_or_try_init(|| {
        info!("Building STARK prover (first call — will be cached for reuse)");
        ProverClientBuilder::new()
            .asm()
            .prove()
            .aggregation(true)
            .proving_key_path(config.proving_key.clone())
            .proving_key_snark_path(config.proving_key_snark.clone())
            .verbose(0)
            .shared_tables(true)
            .unlock_mapped_memory(false)
            .base_port(STARK_BASE_PORT)
            .print_command_info()
            .build::<fields::Goldilocks>()
            .map_err(|e| ProverError::GuestError(format!("Failed to build STARK prover: {e}")))
    })
}

fn cached_snark_prover(config: &ZiskLocalConfig) -> ProverResult<&'static ZiskProver<Asm>> {
    SNARK_PROVER.get_or_try_init(|| {
        info!("Building SNARK prover (first call — will be cached for reuse)");
        ProverClientBuilder::new()
            .asm()
            .prove()
            .aggregation(true)
            .snark()
            .proving_key_path(config.proving_key.clone())
            .proving_key_snark_path(config.proving_key_snark.clone())
            .verbose(0)
            .shared_tables(true)
            .unlock_mapped_memory(false)
            .base_port(SNARK_BASE_PORT)
            .print_command_info()
            .build::<fields::Goldilocks>()
            .map_err(|e| ProverError::GuestError(format!("Failed to build SNARK prover: {e}")))
    })
}

fn cached_pk(
    prover: &ZiskProver<Asm>,
    elf_name: &str,
) -> ProverResult<&'static (ZiskProgramPK, ZiskProgramVK)> {
    let cache: &OnceCell<(ZiskProgramPK, ZiskProgramVK)> = match elf_name {
        "zisk-batch" => &BATCH_PK,
        "zisk-aggregation" => &AGG_PK,
        "zisk-shasta-aggregation" => &SHASTA_AGG_PK,
        _ => return Err(ProverError::GuestError(format!("Unknown ELF: {elf_name}"))),
    };
    cache.get_or_try_init(|| {
        info!(
            "Setting up PK for {} (first call — will be cached, includes ROM setup if needed)",
            elf_name
        );
        let elf = elf_path(elf_name);
        let elf_binary = ElfBinaryFromFile::new(&elf, false)
            .map_err(|e| ProverError::GuestError(format!("Failed to read ELF: {e}")))?;
        prover
            .setup(&elf_binary)
            .map_err(|e| ProverError::GuestError(format!("Failed to setup {elf_name}: {e}")))
    })
}

/// Get the vkey hex for an ELF, derived from the cached PK/VK.
/// On first access this builds the prover and runs setup (incl. ROM setup).
fn cached_vkey_hex(elf_name: &str) -> ProverResult<String> {
    let config = ZiskLocalConfig::from_env();
    let prover = match elf_name {
        "zisk-batch" => cached_stark_prover(&config)?,
        _ => cached_snark_prover(&config)?,
    };
    let (_pk, vk) = cached_pk(prover, elf_name)?;
    Ok(format!("0x{}", hex::encode(&vk.vk)))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn save_input(elf_name: &str, serialized_input: &[u8], config: &ZiskLocalConfig) {
    std::fs::create_dir_all(&config.output_dir).ok();
    let input_path = config.output_dir.join(format!("{elf_name}-input.bin"));
    std::fs::write(&input_path, serialized_input).ok();
    info!(
        "Saved {} input ({} bytes) to {:?}",
        elf_name,
        serialized_input.len(),
        input_path
    );
}

fn prove_stark(
    elf_name: &str,
    serialized_input: Vec<u8>,
    config: &ZiskLocalConfig,
) -> ProverResult<ZiskProveResult> {
    info!("Using ELF at {:?}", elf_path(elf_name));
    save_input(elf_name, &serialized_input, config);

    let prover = cached_stark_prover(config)?;
    let (pk, _vk) = cached_pk(prover, elf_name)?;

    let stdin = zisk_common::io::ZiskStdin::from_vec(serialized_input);
    let proof_opts = ProofOpts::default()
        .output_dir(config.output_dir.clone())
        .verify_proofs();

    let result = prover
        .prove(pk, stdin)
        .with_proof_options(proof_opts)
        .run()
        .map_err(|e| ProverError::GuestError(format!("Zisk STARK proof failed: {e}")))?;

    Ok(result)
}

fn prove_stark_with_snark(
    elf_name: &str,
    serialized_input: Vec<u8>,
    config: &ZiskLocalConfig,
) -> ProverResult<ZiskProveResult> {
    info!("Using ELF at {:?}", elf_path(elf_name));
    save_input(elf_name, &serialized_input, config);

    let prover = cached_snark_prover(config)?;
    let (pk, _vk) = cached_pk(prover, elf_name)?;

    let stdin = zisk_common::io::ZiskStdin::from_vec(serialized_input);
    let proof_opts = ProofOpts::default()
        .output_dir(config.output_dir.clone())
        .verify_proofs();

    let result = prover
        .prove(pk, stdin)
        .plonk()
        .with_proof_options(proof_opts)
        .run()
        .map_err(|e| ProverError::GuestError(format!("Zisk SNARK proof failed: {e}")))?;

    Ok(result)
}

fn zisk_proof_to_bytes(proof: &ZiskProof) -> ProverResult<Vec<u8>> {
    match proof {
        ZiskProof::VadcopFinal(bytes) | ZiskProof::VadcopFinalCompressed(bytes) => {
            Ok(bytes.clone())
        }
        ZiskProof::Plonk(bytes) | ZiskProof::Fflonk(bytes) => Ok(bytes.clone()),
        ZiskProof::Null() => Err(ProverError::GuestError("Proof is Null".into())),
    }
}

fn stark_proof_to_raiko_proof(
    result: &ZiskProveResult,
    output_hash: B256,
    vkey: Option<String>,
) -> ProverResult<Proof> {
    let proof_bytes = zisk_proof_to_bytes(result.get_proof())?;
    Ok(Proof {
        proof: Some(format!("0x{}", hex::encode(&proof_bytes))),
        quote: None,
        input: Some(output_hash),
        uuid: vkey,
        kzg_proof: None,
        extra_data: None,
    })
}

fn snark_proof_to_raiko_proof(
    result: &ZiskProveResult,
    output_hash: B256,
    vkey: Option<String>,
) -> ProverResult<Proof> {
    let proof_bytes = zisk_proof_to_bytes(result.get_proof())?;
    // For SNARK proofs, publics are encoded separately
    let program_vk = result.get_program_vk();
    Ok(Proof {
        proof: Some(format!("0x{}", hex::encode(&proof_bytes))),
        quote: Some(hex::encode(&program_vk.vk)),
        input: Some(output_hash),
        uuid: vkey,
        kzg_proof: None,
        extra_data: None,
    })
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
        info!("Zisk local batch proof starting");

        let serialized_input = bincode::serialize(&input).map_err(|e| {
            ProverError::GuestError(format!("Failed to serialize GuestBatchInput: {e}"))
        })?;

        let output_hash = output.hash;
        let proof = tokio::task::spawn_blocking(move || {
            let batch_vkey = cached_vkey_hex("zisk-batch")?;
            let config = ZiskLocalConfig::from_env();
            let result = prove_stark("zisk-batch", serialized_input, &config)?;
            stark_proof_to_raiko_proof(&result, output_hash, Some(batch_vkey))
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

        let batch_vkey = cached_vkey_hex("zisk-batch")?;
        let zisk_input = ZkAggregationGuestInput {
            image_id: vkey_to_image_id(&batch_vkey),
            block_inputs,
        };
        let serialized_input = bincode::serialize(&zisk_input).map_err(|e| {
            ProverError::GuestError(format!("Failed to serialize aggregation input: {e}"))
        })?;

        let output_hash = output.hash;
        let proof = tokio::task::spawn_blocking(move || {
            let agg_vkey = cached_vkey_hex("zisk-aggregation")?;
            let config = ZiskLocalConfig::from_env();
            let result = prove_stark_with_snark("zisk-aggregation", serialized_input, &config)?;
            snark_proof_to_raiko_proof(&result, output_hash, Some(agg_vkey))
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

        let batch_vkey = cached_vkey_hex("zisk-batch")?;
        let shasta_input = ShastaZiskAggregationGuestInput {
            image_id: vkey_to_image_id(&batch_vkey),
            block_inputs,
            proof_carry_data_vec,
            prover_address: Address::ZERO,
        };
        let serialized_input = bincode::serialize(&shasta_input).map_err(|e| {
            ProverError::GuestError(format!("Failed to serialize shasta input: {e}"))
        })?;

        let output_hash = output.hash;
        let proof = tokio::task::spawn_blocking(move || {
            let shasta_vkey = cached_vkey_hex("zisk-shasta-aggregation")?;
            let config = ZiskLocalConfig::from_env();
            let result =
                prove_stark_with_snark("zisk-shasta-aggregation", serialized_input, &config)?;
            snark_proof_to_raiko_proof(&result, output_hash, Some(shasta_vkey))
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
        // This initializes provers + runs ROM setup on first call.
        // All subsequent calls return cached results instantly.
        let data = tokio::task::spawn_blocking(|| -> ProverResult<serde_json::Value> {
            let batch_vkey = cached_vkey_hex("zisk-batch")?;
            let agg_vkey = cached_vkey_hex("zisk-aggregation")?;
            let shasta_agg_vkey = cached_vkey_hex("zisk-shasta-aggregation")?;
            Ok(json!({
                "zisk": {
                    "batch_vkey": batch_vkey,
                    "aggregation_vkey": agg_vkey,
                    "shasta_aggregation_vkey": shasta_agg_vkey,
                }
            }))
        })
        .await
        .map_err(|e| ProverError::GuestError(format!("spawn_blocking failed: {e}")))??;

        Ok(data)
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
