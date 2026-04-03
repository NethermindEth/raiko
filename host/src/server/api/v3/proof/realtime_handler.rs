use crate::{
    interfaces::HostResult,
    server::{
        api::v3::{ProofResponse, Status},
        auth::AuthenticatedApiKey,
        handler::prove,
        utils::{
            draw_shasta_sgx_request, draw_shasta_zk_request, is_sgx_any_request, is_zk_any_request,
            to_v3_status,
        },
    },
};
use axum::{extract::State, routing::post, Extension, Json, Router};
use raiko_core::{
    interfaces::{RaikoError, RealTimeProofRequest, RealTimeProofRequestOpt},
    merge,
};
use raiko_lib::proof_type::ProofType;
use raiko_reqactor::Actor;
use raiko_reqpool::ImageId;
use raiko_tasks::TaskStatus;
use serde_json::Value;
use utoipa::OpenApi;

use super::batch::process_realtime_request;

#[utoipa::path(post, path = "/batch/realtime",
    tag = "Proving",
    request_body = RealTimeProofRequest,
    responses (
        (status = 200, description = "Successfully submitted RealTime proof task, queried task in progress or retrieved proof.", body = Status)
    )
)]
/// Submit a RealTime proof task with requested config, get task status or get proof value.
///
/// Accepts a RealTime proof request for atomic propose+prove.
/// Unlike Shasta, there is no aggregation — one proposal per proof per transaction.
async fn realtime_handler(
    State(actor): State<Actor>,
    Extension(authenticated_key): Extension<AuthenticatedApiKey>,
    Json(mut realtime_request_opt): Json<Value>,
) -> HostResult<Status> {
    tracing::info!(
        "Incoming RealTime request from {}, l2_block_numbers: {}, proof_type: {}",
        authenticated_key.name,
        &realtime_request_opt["l2_block_numbers"],
        &realtime_request_opt["proof_type"],
    );
    tracing::debug!(
        "Incoming RealTime request full payload: {}",
        serde_json::to_string(&realtime_request_opt)?,
    );

    // For zk_any request, draw zk proof type.
    // Use the first L2 block number as a pseudo batch_id for drawing.
    if is_zk_any_request(&realtime_request_opt) {
        let first_block = realtime_request_opt["l2_block_numbers"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let max_anchor = realtime_request_opt["max_anchor_block_number"]
            .as_u64()
            .unwrap_or(0);

        match draw_shasta_zk_request(&actor, first_block, max_anchor).await? {
            Some(proof_type) => {
                realtime_request_opt["proof_type"] = serde_json::to_value(proof_type).unwrap()
            }
            None => {
                return Ok(Status::Ok {
                    proof_type: ProofType::Native,
                    batch_id: None,
                    data: ProofResponse::Status {
                        status: TaskStatus::ZKAnyNotDrawn,
                    },
                });
            }
        }
    }

    // For sgx_any request, draw sgx proof type.
    if is_sgx_any_request(&realtime_request_opt) {
        let first_block = realtime_request_opt["l2_block_numbers"]
            .as_array()
            .and_then(|a| a.first())
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let max_anchor = realtime_request_opt["max_anchor_block_number"]
            .as_u64()
            .unwrap_or(0);

        match draw_shasta_sgx_request(&actor, first_block, max_anchor).await? {
            Some(proof_type) => {
                realtime_request_opt["proof_type"] = serde_json::to_value(proof_type).unwrap()
            }
            None => {
                return Ok(Status::Ok {
                    proof_type: ProofType::Native,
                    batch_id: None,
                    data: ProofResponse::Status {
                        status: TaskStatus::ZKAnyNotDrawn,
                    },
                });
            }
        }
    }

    let realtime_request: RealTimeProofRequest =
        finalize_realtime_request(&actor, realtime_request_opt)?;

    tracing::info!(
        "Accepted {}'s RealTime request, l2_blocks: {:?}, proof_type: {:?}, network: {}",
        authenticated_key.name,
        realtime_request.l2_block_numbers,
        realtime_request.proof_type,
        realtime_request.network,
    );
    tracing::trace!(
        "Accepted RealTime request full payload: {}",
        serde_json::to_string(&realtime_request)?,
    );

    // Fetch L2 block hashes from RPC to use as part of the cache key.
    let mut l2_block_hashes = Vec::with_capacity(realtime_request.l2_block_numbers.len());
    for &block_number in &realtime_request.l2_block_numbers {
        let (_, block_hash) = raiko_core::provider::get_task_data(
            &realtime_request.network,
            block_number,
            actor.chain_specs(),
        )
        .await?;
        l2_block_hashes.push(block_hash);
    }

    // No aggregation for RealTime
    let image_id = ImageId::from_proof_type_and_request_type(&realtime_request.proof_type, false);

    let (_input_request_key, proof_request_key, _input_request_entity, proof_request_entity) =
        process_realtime_request(&realtime_request, &image_id, l2_block_hashes);

    // When sources is empty, this is a status poll — don't submit for proving.
    // The caller sends the first request with full sources+blobs to kick off proving,
    // then polls with empty sources to check progress.
    let is_poll = realtime_request.sources.is_empty();

    if is_poll {
        let result = actor
            .pool_get_status(&proof_request_key.clone().into())
            .await;
        let status = match result {
            Ok(Some(status_with_context)) => to_v3_status(
                realtime_request.proof_type,
                None,
                Ok(status_with_context.into_status()),
            ),
            Ok(None) => {
                // No status found — proof expired via Redis TTL or never submitted
                to_v3_status(
                    realtime_request.proof_type,
                    None,
                    Ok(raiko_reqpool::Status::Registered),
                )
            }
            Err(e) => to_v3_status(realtime_request.proof_type, None, Err(e)),
        };
        return Ok(status);
    }

    // If use_cache is false, evict existing proof to force re-proving.
    if !realtime_request.use_cache {
        let _ = actor
            .pool_remove_request(&proof_request_key.clone().into())
            .await;
    }

    // Submit proof directly — do_prove_realtime will generate guest input
    // inline if it's not already in prover_args, so no separate guest input
    // stage is needed.
    let result = prove(
        &actor,
        proof_request_key.clone().into(),
        proof_request_entity,
    )
    .await;

    let status = to_v3_status(realtime_request.proof_type, None, result);
    Ok(status)
}

fn finalize_realtime_request(
    actor: &Actor,
    realtime_request_opt: Value,
) -> Result<RealTimeProofRequest, RaikoError> {
    let mut opts = serde_json::to_value(actor.default_request_config())?;
    merge(&mut opts, &realtime_request_opt);

    let realtime_request_opt: RealTimeProofRequestOpt = serde_json::from_value(opts)?;
    let realtime_request: RealTimeProofRequest = realtime_request_opt.try_into()?;

    if realtime_request.l2_block_numbers.is_empty() {
        return Err(anyhow::anyhow!("l2_block_numbers is empty").into());
    }

    Ok(realtime_request)
}

#[derive(OpenApi)]
#[openapi(paths(realtime_handler))]
struct Docs;

pub fn create_docs() -> utoipa::openapi::OpenApi {
    Docs::openapi()
}

pub fn create_router() -> Router<Actor> {
    Router::new().route("/", post(realtime_handler))
}
