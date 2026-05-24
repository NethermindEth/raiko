use alethia_reth_consensus::transaction::TaikoTxEnvelope;
use alethia_reth_consensus::validation::ANCHOR_V3_V4_GAS_LIMIT;
use alethia_reth_evm::spec::TaikoSpecId;
use alloy_rlp::Decodable;
use log::warn;

use crate::consts::ForkCondition;
use crate::input::GuestBatchInput;
use crate::manifest::DerivationSourceManifest;
#[cfg(not(feature = "std"))]
use crate::no_std::*;
use crate::privacy::{self, DecryptKeys};
use crate::utils::blobs::{decode_blob_data, zlib_decompress_data};

/// Parses a hex-encoded 32-byte value (with or without `0x` prefix) at compile time
/// or runtime. Returns `None` on malformed input.
fn parse_hex_32(s: &str) -> Option<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
        out[i] = byte;
    }
    Some(out)
}
use crate::utils::shasta_rules::{
    clamp_timestamp_lower_bound, validate_force_inc_proposal_manifest, validate_input_block_param,
    validate_realtime_proposal_manifest, validate_shasta_block_base_fee,
};

fn make_default_manifest_realtime(
    guest_batch_input: &GuestBatchInput,
    last_parent_block_timestamp: u64,
    last_parent_block_gas_limit: u64,
    last_anchor_block_number: u64,
) -> DerivationSourceManifest {
    let taiko_guest_batch_input = &guest_batch_input.taiko;
    let proposal_timestamp = taiko_guest_batch_input.batch_proposed.proposal_timestamp();
    let realtime_fork_timestamp = match guest_batch_input
        .taiko
        .chain_spec
        .hard_forks
        .get(&TaikoSpecId::REALTIME)
    {
        Some(ForkCondition::Timestamp(timestamp)) => *timestamp,
        Some(ForkCondition::Block(_)) => 0, // Block-based fork has no timestamp lower bound
        _ => 0,
    };
    let timestamp = clamp_timestamp_lower_bound(
        last_parent_block_timestamp,
        proposal_timestamp,
        realtime_fork_timestamp,
    );
    let coinbase = taiko_guest_batch_input.batch_proposed.proposer();
    let anchor_block_number = last_anchor_block_number;
    let gas_limit = if guest_batch_input
        .inputs
        .first()
        .unwrap()
        .parent_header
        .number
        == 0
    {
        last_parent_block_gas_limit
    } else {
        last_parent_block_gas_limit - ANCHOR_V3_V4_GAS_LIMIT
    };
    let transactions = Vec::new();
    DerivationSourceManifest::default_block_manifest(
        timestamp,
        coinbase,
        anchor_block_number,
        gas_limit,
        transactions,
    )
}

/// Generate transactions for RealTime blocks.
/// Similar to Shasta but uses REALTIME fork configuration.
pub fn generate_transactions_for_realtime_blocks(
    guest_batch_input: &GuestBatchInput,
) -> Vec<(Vec<TaikoTxEnvelope>, bool)> {
    let taiko_guest_batch_input = &guest_batch_input.taiko;
    let batch_proposal = &taiko_guest_batch_input.batch_proposed;
    let data_sources = &taiko_guest_batch_input.data_sources;
    let mut tx_list_bufs = Vec::new();

    let last_anchor_block_number = guest_batch_input
        .taiko
        .prover_data
        .last_anchor_block_number
        .unwrap();
    let last_parent_block_header = &guest_batch_input.inputs[0].parent_header;
    let mut last_parent_block_timestamp = last_parent_block_header.timestamp;
    let mut last_parent_block_gas_limit = last_parent_block_header.gas_limit;

    // Privacy keys forwarded by the host. Identical for every source within a batch.
    //
    // Bind the witness keys to compile-time hashes baked into the guest. The hash
    // hex is provided via `SURGE_PRIVACY_*_KEY_HASH` build-time env vars; when
    // unset we fall back to `0x00..00` and bypass the check (non-privacy builds).
    // The hash check is what makes the proof's vkey commit to the keys without
    // leaking the secret bytes through the public input.
    if let Some(ref key) = taiko_guest_batch_input.privacy_symmetric_key {
        if let Some(hash_hex) = option_env!("SURGE_PRIVACY_SYMMETRIC_KEY_HASH") {
            if let Some(expected) = parse_hex_32(hash_hex) {
                if expected != [0u8; 32] {
                    privacy::assert_key_hash(key, &expected)
                        .expect("privacy symmetric key hash mismatch — guest vkey rejects this key");
                }
            }
        }
    }
    if let Some(ref key) = taiko_guest_batch_input.privacy_fi_private_key {
        if let Some(hash_hex) = option_env!("SURGE_PRIVACY_FI_PRIVKEY_HASH") {
            if let Some(expected) = parse_hex_32(hash_hex) {
                if expected != [0u8; 32] {
                    privacy::assert_key_hash(key, &expected)
                        .expect("privacy FI private key hash mismatch — guest vkey rejects this key");
                }
            }
        }
    }
    let privacy_keys = DecryptKeys {
        symmetric: taiko_guest_batch_input.privacy_symmetric_key,
        fi_private: taiko_guest_batch_input.privacy_fi_private_key,
    };

    for (idx, data_source) in data_sources.iter().enumerate() {
        let use_blob = batch_proposal.blob_used();
        let compressed_tx_list_buf = if use_blob {
            let blob_data_bufs = data_source.tx_data_from_blob.clone();
            let decoded_blob_data_concat = blob_data_bufs
                .iter()
                .map(|blob_data_buf| decode_blob_data(blob_data_buf))
                .collect::<Vec<Vec<u8>>>()
                .concat();
            let sliced = batch_proposal
                .blob_tx_slice_param_for_source(idx, &decoded_blob_data_concat)
                .and_then(|(blob_offset, blob_size)| {
                    tracing::info!("blob_offset: {blob_offset}, blob_size: {blob_size}");
                    decoded_blob_data_concat
                        .get(blob_offset..blob_offset + blob_size)
                        .map(|s| s.to_vec())
                })
                .unwrap_or_default();

            // Privacy: dispatch on the leading scheme byte. For scheme 0x00 this is a
            // pass-through (returns the bytes after the prefix). For 0x01 / 0x02 this
            // decrypts using the witness-supplied keys. On failure for non-FI sources
            // the caller will fall through to the default-manifest fallback below
            // (matching the driver's behavior); for FI sources the same fallback path
            // already handles arbitrary garbage payloads.
            match privacy::dispatch_decrypt(&sliced, &privacy_keys) {
                Ok(plaintext) => plaintext,
                Err(e) => {
                    warn!(
                        "privacy dispatch failed for source idx={}, is_forced_inclusion={}: {:?}",
                        idx, data_source.is_forced_inclusion, e
                    );
                    Vec::new()
                }
            }
        } else {
            unreachable!("realtime does not use calldata");
        };

        if idx == data_sources.len() - 1 {
            assert!(
                !data_source.is_forced_inclusion,
                "last source should be normal source"
            );
            let protocol_manifest_bytes =
                zlib_decompress_data(&compressed_tx_list_buf).unwrap_or_default();
            let protocol_manifest =
                match DerivationSourceManifest::decode(&mut protocol_manifest_bytes.as_ref()) {
                    Ok(manifest)
                        if validate_realtime_proposal_manifest(&guest_batch_input, &manifest) =>
                    {
                        let is_first_realtime_proposal =
                            guest_batch_input.inputs[0].parent_header.number == 0
                                || guest_batch_input
                                    .taiko
                                    .chain_spec
                                    .active_fork(
                                        guest_batch_input.inputs[0].parent_header.number,
                                        guest_batch_input.inputs[0].parent_header.timestamp,
                                    )
                                    .unwrap()
                                    == TaikoSpecId::PACAYA;

                        if !validate_shasta_block_base_fee(
                            &guest_batch_input.inputs,
                            is_first_realtime_proposal,
                            guest_batch_input.taiko.l2_grandparent_header.as_ref(),
                        ) {
                            warn!("realtime block base fee is invalid, need double check");
                            make_default_manifest_realtime(
                                guest_batch_input,
                                last_parent_block_timestamp,
                                last_parent_block_gas_limit,
                                last_anchor_block_number,
                            )
                        } else {
                            manifest
                        }
                    }
                    _ => {
                        let manifest = make_default_manifest_realtime(
                            guest_batch_input,
                            last_parent_block_timestamp,
                            last_parent_block_gas_limit,
                            last_anchor_block_number,
                        );
                        warn!(
                            "realtime block manifest is invalid, use default manifest: {:?}",
                            &manifest
                        );
                        manifest
                    }
                };

            protocol_manifest
                .blocks
                .iter()
                .enumerate()
                .for_each(|(offset, block_manifest)| {
                    assert!(
                        validate_input_block_param(
                            block_manifest,
                            &guest_batch_input.inputs[idx + offset].block
                        ),
                        "input block manifest is invalid"
                    );
                    tx_list_bufs.push((block_manifest.transactions.clone(), false))
                });
        } else {
            assert!(
                data_source.is_forced_inclusion,
                "begin sources are force inclusion source"
            );

            let force_inc_source_bytes =
                zlib_decompress_data(&compressed_tx_list_buf).unwrap_or_default();
            let force_inc_source =
                match DerivationSourceManifest::decode(&mut force_inc_source_bytes.as_ref()) {
                    Ok(manifest) if validate_force_inc_proposal_manifest(&manifest) => {
                        let mut force_inc_manifest = make_default_manifest_realtime(
                            guest_batch_input,
                            last_parent_block_timestamp,
                            last_parent_block_gas_limit,
                            last_anchor_block_number,
                        );
                        force_inc_manifest.blocks[0].transactions =
                            manifest.blocks[0].transactions.clone();
                        force_inc_manifest
                    }
                    _ => {
                        let manifest = make_default_manifest_realtime(
                            guest_batch_input,
                            last_parent_block_timestamp,
                            last_parent_block_gas_limit,
                            last_anchor_block_number,
                        );
                        warn!(
                            "force inclusion block manifest is invalid, use default manifest: {:?}",
                            &manifest
                        );
                        manifest
                    }
                };

            let force_inc_block_manifest = &force_inc_source.blocks[0];
            last_parent_block_timestamp = force_inc_block_manifest.timestamp;
            last_parent_block_gas_limit = force_inc_block_manifest.gas_limit;
            assert!(
                validate_input_block_param(
                    force_inc_block_manifest,
                    &guest_batch_input.inputs[idx].block
                ),
                "force inclusion source is invalid"
            );
            tx_list_bufs.push((force_inc_block_manifest.transactions.clone(), true));
        }
    }
    tx_list_bufs
}
