use alloy_primitives::B256;
use alloy_sol_types::sol;
use core::fmt::Debug;
use serde::{Deserialize, Serialize};

sol! {
    // Shared types redefined for sol! ABI encoding compatibility.
    // These mirror the definitions in shasta.rs.

    #[derive(Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
    struct BlobSlice {
        bytes32[] blobHashes;
        uint24 offset;
        uint48 timestamp;
    }

    #[derive(Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
    struct Checkpoint {
        uint48 blockNumber;
        bytes32 blockHash;
        bytes32 stateRoot;
    }

    #[derive(Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
    struct DerivationSource {
        bool isForcedInclusion;
        BlobSlice blobSlice;
    }

    #[derive(Debug, Default, Deserialize, Serialize)]
    /// @notice Represents a RealTime proposal (transient, never stored on-chain).
    /// Maps to IRealTimeInbox.Proposal.
    struct RealTimeProposal {
        /// @notice Hash of the parent proposal (zero for genesis).
        bytes32 parentProposalHash;
        /// @notice The highest L1 block the L2 derivation references.
        uint48 maxAnchorBlockNumber;
        /// @notice The hash of the max anchor block.
        bytes32 maxAnchorBlockHash;
        /// @notice The percentage of base fee paid to coinbase.
        uint8 basefeeSharingPctg;
        /// @notice Array of derivation sources (reuses IInbox.DerivationSource).
        DerivationSource[] sources;
        /// @notice Hash of the signal slots to relay.
        /// Empty → bytes32(0), non-empty → keccak256(abi.encode(signalSlots)).
        bytes32 signalSlotsHash;
    }

    #[derive(Debug, Default, Deserialize, Serialize)]
    /// @notice Maps to IRealTimeInbox.Commitment (one proposal, no batching).
    struct RealTimeCommitment {
        /// @notice The hash of the proposal being proven.
        bytes32 proposalHash;
        /// @notice The checkpoint after executing the proposal.
        Checkpoint checkpoint;
    }

    #[derive(Debug, Default, Deserialize, Serialize)]
    /// @notice Emitted after atomic propose+prove on RealTimeInbox.
    event ProposedAndProved(
        bytes32 indexed proposalHash,
        bytes32 parentProposalHash,
        uint48 maxAnchorBlockNumber,
        uint8 basefeeSharingPctg,
        DerivationSource[] sources,
        bytes32 signalSlotsHash,
        Checkpoint checkpoint
    );
}

/// Decoded RealTime event data containing the proposal and signal slots.
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RealTimeEventData {
    pub proposal: RealTimeProposal,
    /// Raw signal slots, needed for hash verification.
    pub signal_slots: Vec<B256>,
}
