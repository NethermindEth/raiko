use alloy_consensus::Blob;
use alloy_primitives::{hex, B256};
use anyhow::{anyhow, ensure, Result};
use kzg::kzg_types::ZFr;
use kzg_traits::{eip_4844::blob_to_kzg_commitment_rust, Fr, G1};
use raiko_lib::{
    input::BlobProofType,
    primitives::eip4844::{self, commitment_to_version_hash, KZG_SETTINGS},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::interfaces::{RaikoError, RaikoResult};

pub async fn get_tx_blob(
    blob_hash: B256,
    timestamp: u64,
    chain_spec: &raiko_lib::consts::ChainSpec,
    blob_proof_type: &BlobProofType,
) -> RaikoResult<(Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>)> {
    debug!("get tx from hash blob: {blob_hash:?}");
    // Get the blob data for this block
    let slot_id = block_time_to_block_slot(
        timestamp,
        chain_spec.genesis_time,
        chain_spec.seconds_per_slot,
    )?;
    info!("get_tx_data: slot_id done");
    let beacon_rpc_url: String = chain_spec.beacon_rpc.clone().ok_or_else(|| {
        RaikoError::Preflight("Beacon RPC URL is required for Taiko chains".to_owned())
    })?;
    let blob = get_and_filter_blob_data(&beacon_rpc_url, slot_id, blob_hash).await?;
    let commitment = eip4844::calc_kzg_proof_commitment(&blob).map_err(|e| anyhow!(e))?;
    let blob_proof = match blob_proof_type {
        BlobProofType::KzgVersionedHash => None,
        BlobProofType::ProofOfEquivalence => {
            let (x, y) =
                eip4844::proof_of_equivalence(&blob, &commitment_to_version_hash(&commitment))
                    .map_err(|e| anyhow!(e))?;

            debug!("x {x:?} y {y:?}");
            let point = eip4844::calc_kzg_proof_with_point(&blob, ZFr::from_bytes(&x).unwrap());
            debug!("calc_kzg_proof_with_point {point:?}");

            Some(
                point
                    .map(|g1| g1.to_bytes().to_vec())
                    .map_err(|e| anyhow!(e))?,
            )
        }
    };

    Ok((blob, Some(commitment.to_vec()), blob_proof))
}

pub async fn filter_tx_blob_beacon_with_proof(
    blob_hash: B256,
    blobs: Vec<String>,
    blob_proof_type: &BlobProofType,
) -> RaikoResult<(Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>)> {
    info!("get tx from hash blob: {blob_hash:?}");
    // Get the blob data for this block
    let blob = filter_blob_data_beacon(blobs, blob_hash).await?;
    let commitment = eip4844::calc_kzg_proof_commitment(&blob).map_err(|e| anyhow!(e))?;
    info!("get_tx_data: commitment done");
    let blob_proof = match blob_proof_type {
        BlobProofType::KzgVersionedHash => None,
        BlobProofType::ProofOfEquivalence => {
            let (x, y) =
                eip4844::proof_of_equivalence(&blob, &commitment_to_version_hash(&commitment))
                    .map_err(|e| anyhow!(e))?;

            debug!("x {x:?} y {y:?}");
            let point = eip4844::calc_kzg_proof_with_point(&blob, ZFr::from_bytes(&x).unwrap());
            debug!("calc_kzg_proof_with_point {point:?}");

            Some(
                point
                    .map(|g1| g1.to_bytes().to_vec())
                    .map_err(|e| anyhow!(e))?,
            )
        }
    };

    info!("get_tx_data: blob_proof done");

    Ok((blob, Some(commitment.to_vec()), blob_proof))
}

/// get tx data(blob data) vec from blob hashes
/// and get proofs for each blobs
pub async fn get_batch_tx_data_with_proofs(
    blob_hashes: Vec<B256>,
    timestamp: u64,
    chain_spec: &raiko_lib::consts::ChainSpec,
    blob_proof_type: &BlobProofType,
) -> RaikoResult<Vec<(Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>)>> {
    let mut tx_data = Vec::new();
    let beacon_rpc_url: String = chain_spec.beacon_rpc.clone().ok_or_else(|| {
        RaikoError::Preflight("Beacon RPC URL is required for Taiko chains".to_owned())
    })?;
    let slot_id = block_time_to_block_slot(
        timestamp,
        chain_spec.genesis_time,
        chain_spec.seconds_per_slot,
    )?;
    // get blob data once
    let blob_data = get_blob_data(&beacon_rpc_url, slot_id).await?;
    let blobs: Vec<String> = blob_data.data.iter().map(|b| b.blob.clone()).collect();
    for hash in blob_hashes {
        let data = filter_tx_blob_beacon_with_proof(hash, blobs.clone(), blob_proof_type).await?;
        tx_data.push(data);
    }
    Ok(tx_data)
}

// block_time_to_block_slot returns the slots of the given timestamp.
pub fn block_time_to_block_slot(
    block_time: u64,
    genesis_time: u64,
    block_per_slot: u64,
) -> RaikoResult<u64> {
    if genesis_time == 0 {
        Err(RaikoError::Anyhow(anyhow!(
            "genesis time is 0, please check chain spec"
        )))
    } else if block_time < genesis_time {
        Err(RaikoError::Anyhow(anyhow!(
            "provided block_time precedes genesis time",
        )))
    } else {
        Ok((block_time - genesis_time) / block_per_slot)
    }
}

pub fn blob_to_bytes(blob_str: &str) -> Vec<u8> {
    hex::decode(blob_str.to_lowercase().trim_start_matches("0x")).unwrap_or_default()
}

fn calc_blob_versioned_hash(blob_str: &str) -> [u8; 32] {
    let blob_bytes = hex::decode(blob_str.to_lowercase().trim_start_matches("0x"))
        .expect("Could not decode blob");
    let blob = Blob::try_from(blob_bytes.as_slice()).expect("Could not create blob from bytes");
    let commitment = blob_to_kzg_commitment_rust(
        &eip4844::deserialize_blob_rust(&blob).expect("Could not deserialize blob"),
        &KZG_SETTINGS.clone(),
    )
    .expect("Could not create kzg commitment from blob");
    commitment_to_version_hash(&commitment.to_bytes()).0
}

async fn get_and_filter_blob_data(
    beacon_rpc_url: &str,
    block_id: u64,
    blob_hash: B256,
) -> Result<Vec<u8>> {
    if beacon_rpc_url.contains("blobscan.com") {
        get_and_filter_blob_data_by_blobscan(beacon_rpc_url, block_id, blob_hash).await
    } else {
        get_and_filter_blob_data_beacon(beacon_rpc_url, block_id, blob_hash).await
    }
}

async fn get_blob_data(beacon_rpc_url: &str, block_id: u64) -> Result<GetBlobsResponse> {
    if beacon_rpc_url.contains("blobscan.com") {
        unimplemented!("blobscan.com is not supported yet")
    } else {
        get_blob_data_beacon(beacon_rpc_url, block_id).await
    }
}

// Blob data from the beacon chain
// type Sidecar struct {
// Index                    string                   `json:"index"`
// Blob                     string                   `json:"blob"`
// SignedBeaconBlockHeader  *SignedBeaconBlockHeader `json:"signed_block_header"`
// KzgCommitment            string                   `json:"kzg_commitment"`
// KzgProof                 string                   `json:"kzg_proof"`
// CommitmentInclusionProof []string
// `json:"kzg_commitment_inclusion_proof"` }
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct GetBlobData {
    pub index: String,
    pub blob: String,
    // pub signed_block_header: SignedBeaconBlockHeader, // ignore for now
    pub kzg_commitment: String,
    pub kzg_proof: String,
    //pub kzg_commitment_inclusion_proof: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct GetBlobsResponse {
    pub data: Vec<GetBlobData>,
}

async fn get_blob_data_beacon(beacon_rpc_url: &str, block_id: u64) -> Result<GetBlobsResponse> {
    let url = format!(
        "{}/eth/v1/beacon/blob_sidecars/{block_id}",
        beacon_rpc_url.trim_end_matches('/'),
    );
    info!("Retrieve blob from {url}.");
    let response = reqwest::get(url.clone()).await?;

    if !response.status().is_success() {
        warn!(
            "Request {url} failed with status code: {}",
            response.status()
        );
        return Err(anyhow::anyhow!(
            "Request failed with status code: {}",
            response.status()
        ));
    }

    let blobs = response.json::<GetBlobsResponse>().await?;
    ensure!(!blobs.data.is_empty(), "blob data not available anymore");
    Ok(blobs)
}

async fn get_and_filter_blob_data_beacon(
    beacon_rpc_url: &str,
    block_id: u64,
    blob_hash: B256,
) -> Result<Vec<u8>> {
    info!("Retrieve blob for {block_id} and expect {blob_hash}.");
    let blobs = get_blob_data_beacon(beacon_rpc_url, block_id).await?;
    // Get the blob data for the blob storing the tx list
    let tx_blob = blobs
        .data
        .iter()
        .find(|blob| {
            // calculate from plain blob
            blob_hash == calc_blob_versioned_hash(&blob.blob)
        })
        .cloned();

    if let Some(tx_blob) = &tx_blob {
        Ok(blob_to_bytes(&tx_blob.blob))
    } else {
        Err(anyhow!("couldn't find blob data matching blob hash"))
    }
}

async fn filter_blob_data_beacon(blobs: Vec<String>, blob_hash: B256) -> Result<Vec<u8>> {
    // Get the blob data for the blob storing the tx list
    let tx_blob = blobs
        .iter()
        .find(|blob| {
            // calculate from plain blob
            blob_hash == calc_blob_versioned_hash(blob)
        })
        .cloned();

    if let Some(tx_blob) = &tx_blob {
        Ok(blob_to_bytes(tx_blob))
    } else {
        Err(anyhow!("couldn't find blob data matching blob hash"))
    }
}

// https://api.blobscan.com/#/
#[derive(Clone, Debug, Deserialize, Serialize)]
struct BlobScanData {
    pub commitment: String,
    pub data: String,
}

async fn get_and_filter_blob_data_by_blobscan(
    beacon_rpc_url: &str,
    _block_id: u64,
    blob_hash: B256,
) -> Result<Vec<u8>> {
    let url = format!("{}/blobs/{blob_hash}", beacon_rpc_url.trim_end_matches('/'),);
    let response = reqwest::get(url.clone()).await?;

    if !response.status().is_success() {
        error!(
            "Request {url} failed with status code: {}",
            response.status()
        );
        return Err(anyhow::anyhow!(
            "Request failed with status code: {}",
            response.status()
        ));
    }

    let blob = response.json::<BlobScanData>().await?;
    Ok(blob_to_bytes(&blob.data))
}

#[cfg(test)]
mod test {
    use alloy_rlp::Decodable;
    use raiko_lib::{
        manifest::DerivationSourceManifest,
        utils::blobs::{decode_blob_data, zlib_decompress_data},
    };

    use super::*;

    #[ignore = "not run in CI as devnet changes frequently"]
    #[tokio::test]
    async fn test_shasta_blob_decoding() -> Result<()> {
        let beacon_rpc_url = "https://l1beacon.internal.taiko.xyz";
        let slot_id = 156;
        let blob_data = get_blob_data(&beacon_rpc_url, slot_id).await.expect("ok");
        println!("blob_data: {blob_data:?}");
        let blob_data = blob_to_bytes(&blob_data.data[0].blob);
        // decompress
        let decoded_blob_data = decode_blob_data(&blob_data);
        println!("decoded_blob_data: {decoded_blob_data:?}");
        let version = B256::from_slice(&decoded_blob_data[0..32]);
        let size = B256::from_slice(&decoded_blob_data[32..64]);
        let size_u64 = usize::from_be_bytes(size.as_slice()[24..32].try_into().unwrap());
        println!("version: {version:?}, size: {size:?}, size_u64: {size_u64}");
        let decompressed_blob_data =
            zlib_decompress_data(&decoded_blob_data[64..64 + size_u64]).expect("ok");
        println!("decompressed_blob_data: {decompressed_blob_data:?}");

        let proposal_manifest =
            DerivationSourceManifest::decode(&mut decompressed_blob_data.as_ref()).unwrap();
        println!("proposal_manifest: {proposal_manifest:?}");
        Ok(())
    }
}
