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
// reusable. We cache one in a static so the first proof pays the init
// cost and all subsequent proofs skip it entirely (~31s saved per proof).
//
// NOTE: MPI can only be initialized once per process (ProofMan::new calls
// MpiCtx::new). We must use a **single prover** for everything. Building
// with .snark() gives us a superset: it can run both STARK-only proofs
// (.run()) and SNARK proofs (.plonk().run()).

static PROVER: Lazy<ZiskProver<Asm>> = Lazy::new(|| {
    info!("Building prover (first call — will be cached for reuse)");

    // Register atexit handler to stop ASM microservices on process exit.
    // Statics are never dropped in Rust, so without this the child processes
    // (mo, mt, rh) would be orphaned.
    unsafe { libc::atexit(shutdown_asm_on_exit) };

    let config = ZiskLocalConfig::from_env();
    ProverClientBuilder::new()
        .asm()
        .prove()
        .aggregation(true)
        .snark()
        .proving_key_path(config.proving_key)
        .proving_key_snark_path(config.proving_key_snark)
        .verbose(0)
        .shared_tables(true)
        .unlock_mapped_memory(false)
        .print_command_info()
        .build::<fields::Goldilocks>()
        .expect("Failed to build prover")
});

fn setup_elf(elf_name: &str) -> (ZiskProgramPK, ZiskProgramVK) {
    info!(
        "Setting up {} (first call — includes ROM setup + ASM services)",
        elf_name
    );
    let elf = elf_path(elf_name);
    let elf_binary = ElfBinaryFromFile::new(&elf, false).expect("Failed to read ELF");
    PROVER
        .setup(&elf_binary)
        .unwrap_or_else(|e| panic!("Failed to setup {elf_name}: {e}"))
}

// Per-ELF proving key (PK) + verification key (VK) caches.
// Each Lazy triggers setup() on first access, starting ASM microservices
// for that ELF. In production, get_guest_data() warms all 3 at startup.
static BATCH_PK: Lazy<(ZiskProgramPK, ZiskProgramVK)> = Lazy::new(|| setup_elf("zisk-batch"));
static AGG_PK: Lazy<(ZiskProgramPK, ZiskProgramVK)> = Lazy::new(|| setup_elf("zisk-aggregation"));
static SHASTA_AGG_PK: Lazy<(ZiskProgramPK, ZiskProgramVK)> =
    Lazy::new(|| setup_elf("zisk-shasta-aggregation"));

fn cached_pk(elf_name: &str) -> &'static (ZiskProgramPK, ZiskProgramVK) {
    match elf_name {
        "zisk-batch" => &BATCH_PK,
        "zisk-aggregation" => &AGG_PK,
        "zisk-shasta-aggregation" => &SHASTA_AGG_PK,
        _ => panic!("Unknown ELF: {elf_name}"),
    }
}

/// Get the vkey hex for an ELF, derived from the cached PK/VK.
/// In production, get_guest_data() warms all 3 ELFs at startup,
/// so subsequent calls are just pointer dereferences.
fn cached_vkey_hex(elf_name: &str) -> String {
    let (_pk, vk) = cached_pk(elf_name);
    format!("0x{}", hex::encode(&vk.vk))
}

// ---------------------------------------------------------------------------
// Shutdown
// ---------------------------------------------------------------------------

extern "C" fn shutdown_asm_on_exit() {
    shutdown_zisk();
}

/// Stop ASM microservices for all initialized ELF proving keys.
/// Called automatically via atexit, but can also be called explicitly
/// for graceful server shutdown.
pub fn shutdown_zisk() {
    info!("Stopping Zisk ASM microservices");
    for (name, pk_lazy) in [
        (
            "zisk-batch",
            &BATCH_PK as &Lazy<(ZiskProgramPK, ZiskProgramVK)>,
        ),
        ("zisk-aggregation", &AGG_PK),
        ("zisk-shasta-aggregation", &SHASTA_AGG_PK),
    ] {
        // Lazy::get returns None if the static was never initialized,
        // avoiding an expensive setup_elf call at exit time.
        if let Some((pk, _vk)) = Lazy::get(pk_lazy) {
            if let Some(asm) = &pk.asm_services {
                info!("Stopping ASM services for {name}");
                if let Err(e) = asm.stop_asm_services() {
                    tracing::error!("Failed to stop ASM services for {name}: {e}");
                }
            }
        }
    }
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

fn prove_stark(elf_name: &str, serialized_input: Vec<u8>) -> ProverResult<ZiskProveResult> {
    let config = ZiskLocalConfig::from_env();
    info!("Using ELF at {:?}", elf_path(elf_name));
    save_input(elf_name, &serialized_input, &config);

    let (pk, _vk) = cached_pk(elf_name);

    let stdin = zisk_common::io::ZiskStdin::from_vec(serialized_input);
    let proof_opts = ProofOpts::default()
        .output_dir(config.output_dir)
        .verify_proofs();

    let result = PROVER
        .prove(pk, stdin)
        .with_proof_options(proof_opts)
        .run()
        .map_err(|e| ProverError::GuestError(format!("Zisk STARK proof failed: {e}")))?;

    Ok(result)
}

fn prove_stark_with_snark(
    elf_name: &str,
    serialized_input: Vec<u8>,
) -> ProverResult<ZiskProveResult> {
    let config = ZiskLocalConfig::from_env();
    info!("Using ELF at {:?}", elf_path(elf_name));
    save_input(elf_name, &serialized_input, &config);

    let (pk, _vk) = cached_pk(elf_name);

    let stdin = zisk_common::io::ZiskStdin::from_vec(serialized_input);
    let proof_opts = ProofOpts::default()
        .output_dir(config.output_dir)
        .verify_proofs();

    let result = PROVER
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
            let batch_vkey = cached_vkey_hex("zisk-batch");
            let result = prove_stark("zisk-batch", serialized_input)?;
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

        let batch_vkey = cached_vkey_hex("zisk-batch");
        let zisk_input = ZkAggregationGuestInput {
            image_id: vkey_to_image_id(&batch_vkey),
            block_inputs,
        };
        let serialized_input = bincode::serialize(&zisk_input).map_err(|e| {
            ProverError::GuestError(format!("Failed to serialize aggregation input: {e}"))
        })?;

        let output_hash = output.hash;
        let proof = tokio::task::spawn_blocking(move || {
            let agg_vkey = cached_vkey_hex("zisk-aggregation");
            let result = prove_stark_with_snark("zisk-aggregation", serialized_input)?;
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

        let batch_vkey = cached_vkey_hex("zisk-batch");
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
            let shasta_vkey = cached_vkey_hex("zisk-shasta-aggregation");
            let result = prove_stark_with_snark("zisk-shasta-aggregation", serialized_input)?;
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
            let batch_vkey = cached_vkey_hex("zisk-batch");
            let agg_vkey = cached_vkey_hex("zisk-aggregation");
            let shasta_agg_vkey = cached_vkey_hex("zisk-shasta-aggregation");
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
