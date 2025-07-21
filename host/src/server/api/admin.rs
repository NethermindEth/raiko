use axum::{extract::State, routing::post, Router, Json};
use serde::{Deserialize, Serialize};

use crate::{interfaces::HostResult, ProverState};

pub fn create_router() -> Router<ProverState> {
    Router::new()
        .route("/admin/pause", post(pause))
        .route("/admin/unpause", post(unpause))
        .route("/admin/tdx/bootstrap", post(tdx_bootstrap))
        .route("/admin/tdx/instance", post(tdx_set_instance_id))
}

async fn pause(State(state): State<ProverState>) -> HostResult<&'static str> {
    state.set_pause(true).await?;
    Ok("System paused successfully")
}

async fn unpause(State(state): State<ProverState>) -> HostResult<&'static str> {
    state.set_pause(false).await?;
    Ok("System unpaused successfully")
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use clap::Parser;
    use std::path::PathBuf;
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_pause() {
        let opts = {
            let mut opts = crate::Opts::parse();
            opts.config_path = PathBuf::from("../host/config/config.json");
            opts.merge_from_file().unwrap();
            opts
        };
        let state = ProverState::init_with_opts(opts).unwrap();
        let app = Router::new()
            .route("/admin/pause", post(pause))
            .with_state(state.clone());

        let request = Request::builder()
            .method("POST")
            .uri("/admin/pause")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.is_paused());
    }

    #[tokio::test]
    async fn test_pause_when_already_paused() {
        let opts = {
            let mut opts = crate::Opts::parse();
            opts.config_path = PathBuf::from("../host/config/config.json");
            opts.merge_from_file().unwrap();
            opts
        };
        let state = ProverState::init_with_opts(opts).unwrap();

        state.set_pause(true).await.unwrap();

        let app = Router::new()
            .route("/admin/pause", post(pause))
            .with_state(state.clone());

        let request = Request::builder()
            .method("POST")
            .uri("/admin/pause")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(state.is_paused());
    }

    #[tokio::test]
    async fn test_unpause() {
        let opts = {
            let mut opts = crate::Opts::parse();
            opts.config_path = PathBuf::from("../host/config/config.json");
            opts.merge_from_file().unwrap();
            opts
        };
        let state = ProverState::init_with_opts(opts).unwrap();

        // Set initial paused state
        state.set_pause(true).await.unwrap();
        assert!(state.is_paused());

        let app = Router::new()
            .route("/admin/unpause", post(unpause))
            .with_state(state.clone());

        let request = Request::builder()
            .method("POST")
            .uri("/admin/unpause")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(!state.is_paused());
    }
}
