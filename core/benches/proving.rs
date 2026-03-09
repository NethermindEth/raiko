use raiko_core::interfaces::{aggregate_shasta_proposals, run_batch_prover};
use raiko_lib::input::{
    AggregationGuestOutput, GuestBatchInput, GuestBatchOutput, ShastaAggregationGuestInput,
};
use raiko_lib::primitives::B256;
use raiko_lib::proof_type::ProofType;
use std::env;
use std::time::Instant;

fn load_fixture<T: serde::de::DeserializeOwned>(env_var: &str, default_path: &str) -> T {
    let path = env::var(env_var).unwrap_or_else(|_| default_path.to_string());
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read fixture file {path}: {e}"));
    serde_json::from_str(&data)
        .unwrap_or_else(|e| panic!("Failed to deserialize fixture file {path}: {e}"))
}

fn proof_type() -> ProofType {
    env::var("PROOF_TYPE")
        .unwrap_or_else(|_| "sp1".to_string())
        .parse()
        .expect("Invalid PROOF_TYPE env var")
}

fn prover_config(proof_type: ProofType) -> serde_json::Value {
    let mut config = serde_json::json!({
        "block_number": 0,
        "batch_id": 0,
        "l1_inclusion_block_number": 0,
        "l2_block_numbers": [],
        "network": "surge_dev",
        "l1_network": "surge_dev_l1",
        "graffiti": "0x0000000000000000000000000000000000000000000000000000000000000000",
        "prover": "0x0000000000000000000000000000000000000000",
        "proof_type": proof_type.to_string(),
        "blob_proof_type": "proof_of_equivalence",
        "prover_args": {},
    });

    match proof_type {
        ProofType::Sp1 => {
            config["sp1"] = serde_json::json!({
                "recursion": "groth16",
                "prover": "local",
                "verify": false,
            });
        }
        _ => {}
    }

    config
}

fn build_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime")
}

fn bench_batch_run(rt: &tokio::runtime::Runtime) {
    let pt = proof_type();
    let input: GuestBatchInput = load_fixture(
        "BENCH_BATCH_INPUT",
        "core/benches/fixtures/batch_input.json",
    );
    let config = prover_config(pt);
    let output = GuestBatchOutput {
        blocks: vec![],
        hash: B256::ZERO,
    };

    println!("=== bench_batch_run (proof_type: {pt}) ===");
    let start = Instant::now();

    let proof = rt.block_on(async {
        run_batch_prover(pt, input, &output, &config, None, None).await
    });

    let elapsed = start.elapsed();
    match proof {
        Ok(p) => println!(
            "batch_run succeeded in {elapsed:.2?}, proof present: {}",
            p.proof.is_some()
        ),
        Err(e) => println!("batch_run failed in {elapsed:.2?}: {e:?}"),
    }
}

fn bench_shasta_aggregate(rt: &tokio::runtime::Runtime) {
    let pt = proof_type();
    let input: ShastaAggregationGuestInput = load_fixture(
        "BENCH_AGG_INPUT",
        "core/benches/fixtures/shasta_agg_input.json",
    );
    let config = prover_config(pt);
    let output = AggregationGuestOutput { hash: B256::ZERO };

    println!("=== bench_shasta_aggregate (proof_type: {pt}) ===");
    let start = Instant::now();

    let proof = rt.block_on(async {
        aggregate_shasta_proposals(pt, input, &output, &config, None, None).await
    });

    let elapsed = start.elapsed();
    match proof {
        Ok(p) => println!(
            "shasta_aggregate succeeded in {elapsed:.2?}, proof present: {}",
            p.proof.is_some()
        ),
        Err(e) => println!("shasta_aggregate failed in {elapsed:.2?}: {e:?}"),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let rt = build_runtime();

    let run_all = args.len() == 1;
    let bench_name = args.get(1).map(|s| s.as_str());

    if run_all || bench_name == Some("batch") {
        bench_batch_run(&rt);
    }
    if run_all || bench_name == Some("aggregate") {
        bench_shasta_aggregate(&rt);
    }

    if !run_all && bench_name != Some("batch") && bench_name != Some("aggregate") {
        eprintln!("Usage: proving [batch|aggregate]");
        eprintln!("  No argument runs both benchmarks.");
        eprintln!();
        eprintln!("Environment variables:");
        eprintln!("  PROOF_TYPE          - Prover to benchmark (sp1, zisk, risc0, ...). Default: sp1");
        eprintln!("  BENCH_BATCH_INPUT   - Path to GuestBatchInput JSON fixture");
        eprintln!("  BENCH_AGG_INPUT     - Path to ShastaAggregationGuestInput JSON fixture");
    }
}
