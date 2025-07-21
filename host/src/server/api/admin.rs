use axum::response::IntoResponse;
use axum::response::Response;
use axum::routing::get;
use axum::Json;
use axum::{extract::State, routing::post, Router};
use raiko_ballot::Ballot;
use raiko_lib::proof_type::ProofType;
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

use crate::interfaces::HostResult;
use raiko_reqactor::Actor;

pub fn create_router() -> Router<Actor> {
    Router::new()
        .route("/pause", post(pause))
        .route("/set_ballot", post(set_ballot))
        .route("/get_ballot", get(get_ballot))
        .route("/tdx/bootstrap", post(tdx_bootstrap))
        .route("/tdx/instance", post(tdx_set_instance_id))
}

async fn pause(State(actor): State<Actor>) -> HostResult<&'static str> {
    actor.pause().await.map_err(|e| anyhow::anyhow!(e))?;
    Ok("System paused successfully")
}

async fn set_ballot(
    State(actor): State<Actor>,
    Json(probs): Json<BTreeMap<ProofType, f64>>,
) -> HostResult<&'static str> {
    let ballot = Ballot::new(probs).map_err(|e| anyhow::anyhow!(e))?;
    actor.set_ballot(ballot);
    Ok("Ballot set successfully")
}

async fn get_ballot(State(actor): State<Actor>) -> Response {
    let ballot = actor.get_ballot().probabilities().to_owned();
    Json(ballot).into_response()
}

#[derive(Deserialize)]
struct TdxInstanceRequest {
    instance_id: u32,
}

#[derive(Serialize)]
struct TdxBootstrapResponse {
    public_key: String,
    message: String,
}

#[cfg(feature = "tdx")]
async fn tdx_bootstrap(_state: State<ProverState>) -> HostResult<Json<TdxBootstrapResponse>> {
    use tdx_prover::{TdxProver, get_config_dir, load_private_key, get_public_key_from_private};
    
    let config_dir = get_config_dir()?;
    
    TdxProver::bootstrap(&config_dir).await?;
    
    let private_key = load_private_key(&config_dir)?;
    let public_key = get_public_key_from_private(&private_key)?;
    
    Ok(Json(TdxBootstrapResponse {
        public_key: format!("0x{}", hex::encode(public_key)),
        message: "TDX prover bootstrapped successfully".to_string(),
    }))
}

#[cfg(not(feature = "tdx"))]
async fn tdx_bootstrap(_state: State<ProverState>) -> HostResult<Json<TdxBootstrapResponse>> {
    Err(anyhow::anyhow!("TDX feature not enabled").into())
}

#[cfg(feature = "tdx")]
async fn tdx_set_instance_id(
    _state: State<ProverState>,
    Json(req): Json<TdxInstanceRequest>,
) -> HostResult<&'static str> {
    use tdx_prover::{TdxProver, get_config_dir};
    
    let config_dir = get_config_dir()?;
    
    TdxProver::set_instance_id(&config_dir, req.instance_id).await?;
    
    Ok("TDX instance ID set successfully")
}

#[cfg(not(feature = "tdx"))]
async fn tdx_set_instance_id(
    _state: State<ProverState>,
    _req: Json<TdxInstanceRequest>,
) -> HostResult<&'static str> {
    Err(anyhow::anyhow!("TDX feature not enabled").into())
}
