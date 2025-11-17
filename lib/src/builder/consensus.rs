use std::{fmt::Debug, sync::Arc};

use alethia_reth_consensus::{
    eip4396::{calculate_next_block_eip4396_base_fee, SHASTA_INITIAL_BASE_FEE},
    validation::TaikoBeaconConsensus,
};
use reth_consensus::{Consensus, ConsensusError, FullConsensus, HeaderValidator};
use reth_consensus_common::validation::validate_against_parent_hash_number;
use reth_evm::block::BlockExecutionResult;
use reth_primitives::{NodePrimitives, SealedBlock};
use reth_primitives_traits::{Block, BlockHeader, GotExpected, RecoveredBlock, SealedHeader};

use alethia_reth_chainspec::{hardfork::TaikoHardforks, spec::TaikoChainSpec};
use reth_storage_api::noop::NoopProvider;
use tracing::debug;

/// Raiko consensus implementation.
///
/// Provides basic checks as outlined in the execution specs.
/// It's just a wrapper around the existing `TaikoBeaconConsensus` that allows to validate
/// blocks without BlockReader.
#[derive(Debug, Clone)]
pub struct RaikoBeaconConsensus {
    chain_spec: Arc<TaikoChainSpec>,
    taiko_beacon_consensus: TaikoBeaconConsensus<NoopProvider>,
    /// The timestamp of the grandparent block, used for base fee calculations in shasta
    /// This value could be None if parent_block_number == 0.
    grandparent_timestamp: Option<u64>,
}

impl RaikoBeaconConsensus {
    /// Create a new instance of [`RaikoBeaconConsensus`]
    pub fn new(chain_spec: Arc<TaikoChainSpec>, grandparent_timestamp: Option<u64>) -> Self {
        Self {
            chain_spec: chain_spec.clone(),
            taiko_beacon_consensus: TaikoBeaconConsensus::new(chain_spec, NoopProvider::default()),
            grandparent_timestamp,
        }
    }
}

/// Just pass invocations to TaikoBeaconConsensus
impl<N> FullConsensus<N> for RaikoBeaconConsensus
where
    N: NodePrimitives,
{
    fn validate_block_post_execution(
        &self,
        block: &RecoveredBlock<N::Block>,
        result: &BlockExecutionResult<N::Receipt>,
    ) -> Result<(), ConsensusError> {
        <TaikoBeaconConsensus<NoopProvider> as FullConsensus<N>>::validate_block_post_execution(
            &self.taiko_beacon_consensus,
            block,
            result,
        )
    }
}

/// Just pass invocations to TaikoBeaconConsensus
impl<B: Block> Consensus<B> for RaikoBeaconConsensus {
    type Error = ConsensusError;

    fn validate_body_against_header(
        &self,
        body: &B::Body,
        header: &SealedHeader<B::Header>,
    ) -> Result<(), ConsensusError> {
        <TaikoBeaconConsensus<NoopProvider> as Consensus<B>>::validate_body_against_header(
            &self.taiko_beacon_consensus,
            body,
            header,
        )
    }

    fn validate_block_pre_execution(&self, block: &SealedBlock<B>) -> Result<(), ConsensusError> {
        self.taiko_beacon_consensus
            .validate_block_pre_execution(block)
    }
}

impl<H> HeaderValidator<H> for RaikoBeaconConsensus
where
    H: BlockHeader,
{
    /// Just pass invocations to TaikoBeaconConsensus
    fn validate_header(&self, header: &SealedHeader<H>) -> Result<(), ConsensusError> {
        self.taiko_beacon_consensus.validate_header(header)
    }

    /// Validate that the header information regarding parent are correct.
    /// This function is not redirected to TaikoBeaconConsensus because it needs BlockProvider,
    /// instead we override it here to provide custom implementation.
    fn validate_header_against_parent(
        &self,
        header: &SealedHeader<H>,
        parent: &SealedHeader<H>,
    ) -> Result<(), ConsensusError> {
        validate_against_parent_hash_number(header.header(), parent)?;

        let header_base_fee = {
            header
                .header()
                .base_fee_per_gas()
                .ok_or(ConsensusError::BaseFeeMissing)?
        };

        if self.chain_spec.is_shasta_active(header.timestamp()) {
            // Shasta hardfork introduces stricter timestamp validation:
            // timestamps must strictly increase (no equal timestamps allowed)
            if header.timestamp() <= parent.timestamp() {
                return Err(ConsensusError::TimestampIsInPast {
                    parent_timestamp: parent.timestamp(),
                    timestamp: header.timestamp(),
                });
            }

            debug!("Calculating expected base fee");
            let expected_base_fee = if parent.number() == 0 {
                debug!("Calculating expected base fee with parent number 0");
                // First post-genesis block lacks a grandparent timestamp, so keep the default base
                // fee.
                SHASTA_INITIAL_BASE_FEE
            } else {
                debug!(
                    "Calculating expected base fee with parent number {}",
                    parent.number()
                );
                calculate_next_block_eip4396_base_fee(
                    parent.header(),
                    parent_block_time(
                        self.grandparent_timestamp
                            .expect("Grandparent timestamp missing"),
                        parent,
                    ),
                )
            };

            // Verify the block's base fee matches the expected value.
            if header_base_fee != expected_base_fee {
                return Err(ConsensusError::BaseFeeDiff(GotExpected {
                    got: header_base_fee,
                    expected: expected_base_fee,
                }));
            }
        } else {
            // For blocks before Shasta, the timestamp must be greater than or equal to the parent's
            // timestamp.
            if header.timestamp() < parent.timestamp() {
                return Err(ConsensusError::TimestampIsInPast {
                    parent_timestamp: parent.timestamp(),
                    timestamp: header.timestamp(),
                });
            }
        }

        Ok(())
    }
}

/// Calculates the time difference between the parent and grandparent blocks.
fn parent_block_time<H>(grandparent_timestamp: u64, parent: &SealedHeader<H>) -> u64
where
    H: BlockHeader,
{
    parent.header().timestamp() - grandparent_timestamp
}
