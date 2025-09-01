//! Taiko's anchor related functionality and checks.

use alloy_consensus::{BlockHeader, TxEip1559};
use alloy_primitives::{uint, Address, TxKind, U256};
use anyhow::{anyhow, bail, ensure, Context, Result};
use once_cell::sync::Lazy;
use reth_primitives::{Header, RecoveredBlock, TransactionSigned};
use std::str::FromStr;

#[derive(Clone, Debug, Default)]
/// Base fee configuration
pub struct ProtocolBaseFeeConfig {
    /// BaseFeeConfig::adjustmentQuotient
    pub adjustment_quotient: u8,
    /// BaseFeeConfig::sharingPctg
    pub sharing_pctg: u8,
    /// BaseFeeConfig::gasIssuancePerSecond
    pub gas_issuance_per_second: u32,
    /// BaseFeeConfig::minGasExcess
    pub min_gas_excess: u64,
    /// BaseFeeConfig::maxGasIssuancePerBlock
    pub max_gas_issuance_per_block: u32,
}

/// Data required to validate a Taiko Block
#[derive(Clone, Debug, Default)]
pub struct TaikoData {
    /// header
    pub l1_header: Header,
    /// parent L1 header
    pub parent_header: Header,
    /// L2 contract
    pub l2_contract: Address,
    /// base fee sharing ratio
    pub base_fee_config: ProtocolBaseFeeConfig,
    /// gas limit to invalidate some extra txs
    /// to align with the client's mining rule
    pub gas_limit: u64,
}

/// Anchor tx gas limit
pub const ANCHOR_GAS_LIMIT: u64 = 250_000;
/// AnchorV3 tx gas limit
pub const ANCHOR_V3_GAS_LIMIT: u64 = 1_000_000;

/// The address calling the anchor transaction
pub static GOLDEN_TOUCH_ACCOUNT: Lazy<Address> = Lazy::new(|| {
    Address::from_str("0x0000777735367b36bC9B61C50022d9D0700dB4Ec")
        .expect("invalid golden touch account")
});
static GX1: U256 = uint!(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798_U256);
static N: U256 = uint!(0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141_U256);
static GX1_MUL_PRIVATEKEY: U256 =
    uint!(0x4341adf5a780b4a87939938fd7a032f6e6664c7da553c121d3b4947429639122_U256);
static GX2: U256 = uint!(0xc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5_U256);

/// check the anchor signature with fixed K value
pub fn check_anchor_signature(anchor: &TransactionSigned) -> Result<()> {
    let sign = anchor.signature();
    if sign.r() == GX1 {
        return Ok(());
    }
    let msg_hash = anchor.signature_hash();
    let msg_hash: U256 = msg_hash.into();
    if sign.r() == GX2 {
        // when r == GX2 require s == 0 if k == 1
        // alias: when r == GX2 require N == msg_hash + *GX1_MUL_PRIVATEKEY
        if N != msg_hash + GX1_MUL_PRIVATEKEY {
            bail!(
                "r == GX2, but N != msg_hash + *GX1_MUL_PRIVATEKEY, N: {}, msg_hash: {msg_hash}, *GX1_MUL_PRIVATEKEY: {}",
                N, GX1_MUL_PRIVATEKEY
            );
        }
        return Ok(());
    }
    Err(anyhow!(
        "r != *GX1 && r != GX2, r: {}, *GX1: {}, GX2: {}",
        sign.r(),
        GX1,
        GX2
    ))
}

use alloy_sol_types::{sol, SolCall};

sol! {
    /// Anchor call
    function anchor(
        /// The L1 hash
        bytes32 l1Hash,
        /// The L1 state root
        bytes32 l1StateRoot,
        /// The L1 block number
        uint64 l1BlockId,
        /// The gas used in the parent block
        uint32 parentGasUsed
    )
        external
    {}

    /// Base fee configuration
    struct BaseFeeConfig {
        /// adjustmentQuotient for eip1559
        uint8 adjustmentQuotient;
        /// sharingPctg for fee sharing
        uint8 sharingPctg;
        /// gasIssuancePerSecond for eip1559
        uint32 gasIssuancePerSecond;
        /// minGasExcess for eip1559
        uint64 minGasExcess;
        /// maxGasIssuancePerBlock for eip1559
        uint32 maxGasIssuancePerBlock;
    }

    function anchorV2(
        /// The anchor L1 block
        uint64 _anchorBlockId,
        /// The anchor block state root
        bytes32 _anchorStateRoot,
        /// The parent gas used
        uint32 _parentGasUsed,
        /// The base fee configuration
        BaseFeeConfig calldata _baseFeeConfig
    )
        external
        nonReentrant
    {}

    function anchorV3(
        uint64 _anchorBlockId,
        bytes32 _anchorStateRoot,
        uint32 _parentGasUsed,
        BaseFeeConfig calldata _baseFeeConfig,
        bytes32[] calldata _signalSlots
    )
        external
        nonReentrant
    {}
}

// todo, use compiled abi once test passes
// sol!(TaikoL2, "./res/TaikoL2.json");
// use TaikoL2::{anchor, anchorV2};

/// Decode anchor tx data
pub fn decode_anchor(bytes: &[u8]) -> Result<anchorCall> {
    anchorCall::abi_decode(bytes).map_err(|e| anyhow!(e))
}

/// decodes an ontake block's extradata, returns `basefee_ratio` configurations,
/// the corresponding encoding function in protocol is `LibProposing._encodeGasConfigs`.
pub fn decode_ontake_extra_data(extradata: &[u8]) -> u8 {
    let basefee_ratio = U256::from_be_slice(extradata);
    let val: u64 = basefee_ratio.try_into().unwrap();
    val as u8
}

/// Verifyes the common conditions for all anchor transactions
pub fn check_common_anchor_conditions<B: reth_primitives_traits::Block>(
    anchor: &TxEip1559,
    tx: &TransactionSigned,
    from: &Address,
    block: &RecoveredBlock<B>,
    taiko_data: &TaikoData,
    anchor_gas_limit: u64,
) -> Result<()> {
    // Check the signature
    check_anchor_signature(tx).context(anyhow!("failed to check anchor signature"))?;

    // Extract the `to` address
    let TxKind::Call(to) = anchor.to else {
        return Err(anyhow!("anchor tx not a smart contract call"));
    };
    // Check that it's from the golden touch address
    ensure!(
        *from == *GOLDEN_TOUCH_ACCOUNT,
        "anchor transaction from mismatch"
    );
    // Check that the L2 contract is being called
    ensure!(
        to == taiko_data.l2_contract,
        "anchor transaction to mismatch"
    );
    // Tx can't have any ETH attached
    ensure!(
        anchor.value == U256::from(0),
        "anchor transaction value mismatch"
    );
    // Tx needs to have the expected gas limit
    ensure!(
        anchor.gas_limit == anchor_gas_limit,
        "anchor transaction gas price mismatch"
    );
    // Check needs to have the base fee set to the block base fee
    ensure!(
        anchor.max_fee_per_gas
            == block
                .base_fee_per_gas()
                .expect("base_fee_per_gas should be present")
                .into(),
        "anchor transaction gas mismatch"
    );

    Ok(())
}

/// Verifies the anchor tx correctness
pub fn check_anchor_tx<B: reth_primitives_traits::Block>(
    tx: &TransactionSigned,
    from: &Address,
    block: &RecoveredBlock<B>,
    taiko_data: TaikoData,
) -> Result<()> {
    let anchor = tx
        .as_eip1559()
        .context(anyhow!("anchor tx is not an EIP1559 tx"))?
        .tx();

    // Default checks for anchor tx
    check_common_anchor_conditions(anchor, tx, from, block, &taiko_data, ANCHOR_GAS_LIMIT)?;

    // Okay now let's decode the anchor tx to verify the inputs
    let anchor_call = decode_anchor(&anchor.input)?;
    // The L1 blockhash needs to match the expected value
    ensure!(
        anchor_call.l1Hash == taiko_data.l1_header.hash_slow(),
        "L1 hash mismatch"
    );
    ensure!(
        anchor_call.l1StateRoot == taiko_data.l1_header.state_root,
        "L1 state root mismatch"
    );
    ensure!(
        anchor_call.l1BlockId == taiko_data.l1_header.number,
        "L1 block number mismatch"
    );
    // The parent gas used input needs to match the gas used value of the parent block
    ensure!(
        anchor_call.parentGasUsed == taiko_data.parent_header.gas_used as u32,
        "parentGasUsed mismatch"
    );

    Ok(())
}

/// Decode anchor tx data for ontake fork, using anchorV2
pub fn decode_anchor_ontake(bytes: &[u8]) -> Result<anchorV2Call> {
    anchorV2Call::abi_decode(bytes).map_err(|e| anyhow!(e))
}

/// Verifies the anchor tx correctness in ontake fork
pub fn check_anchor_tx_ontake<B: reth_primitives_traits::Block>(
    tx: &TransactionSigned,
    from: &Address,
    block: &RecoveredBlock<B>,
    taiko_data: TaikoData,
) -> Result<()> {
    let anchor = tx
        .as_eip1559()
        .context(anyhow!("anchor tx is not an EIP1559 tx"))?
        .tx();

    // Default checks for anchor tx
    check_common_anchor_conditions(anchor, tx, from, block, &taiko_data, ANCHOR_GAS_LIMIT)?;

    // Okay now let's decode the anchor tx to verify the inputs
    let anchor_call = decode_anchor_ontake(&anchor.input)?;
    ensure!(
        anchor_call._anchorBlockId == taiko_data.l1_header.number,
        "L1 block number mismatch"
    );
    ensure!(
        anchor_call._anchorStateRoot == taiko_data.l1_header.state_root,
        "L1 state root mismatch"
    );
    // The parent gas used input needs to match the gas used value of the parent block
    ensure!(
        anchor_call._parentGasUsed == taiko_data.parent_header.gas_used as u32,
        "parentGasUsed mismatch"
    );
    ensure!(
        anchor_call._baseFeeConfig.gasIssuancePerSecond
            == taiko_data.base_fee_config.gas_issuance_per_second,
        "gas issuance per second mismatch"
    );
    ensure!(
        anchor_call._baseFeeConfig.adjustmentQuotient
            == taiko_data.base_fee_config.adjustment_quotient,
        "basefee adjustment quotient mismatch"
    );
    ensure!(
        anchor_call._baseFeeConfig.sharingPctg == taiko_data.base_fee_config.sharing_pctg,
        "basefee ratio mismatch"
    );
    ensure!(
        anchor_call._baseFeeConfig.minGasExcess == taiko_data.base_fee_config.min_gas_excess,
        "min gas excess mismatch"
    );
    ensure!(
        anchor_call._baseFeeConfig.maxGasIssuancePerBlock
            == taiko_data.base_fee_config.max_gas_issuance_per_block,
        "max gas issuance per block mismatch"
    );
    Ok(())
}

/// Decode anchor tx data for pacaya fork, using anchorV3
pub fn decode_anchor_pacaya(bytes: &[u8]) -> Result<anchorV3Call> {
    anchorV3Call::abi_decode(bytes).map_err(|e| anyhow!(e))
}

/// Verifies the anchor tx correctness in pacaya fork
pub fn check_anchor_tx_pacaya<B: reth_primitives_traits::Block>(
    tx: &TransactionSigned,
    from: &Address,
    block: &RecoveredBlock<B>,
    taiko_data: TaikoData,
) -> Result<()> {
    let anchor = tx
        .as_eip1559()
        .context(anyhow!("anchor tx is not an EIP1559 tx"))?
        .tx();

    // Default checks for anchor tx
    check_common_anchor_conditions(anchor, tx, from, block, &taiko_data, ANCHOR_V3_GAS_LIMIT)?;

    // Okay now let's decode the anchor tx to verify the inputs
    let anchor_call = decode_anchor_pacaya(&anchor.input)?;
    ensure!(
        anchor_call._anchorBlockId == taiko_data.l1_header.number,
        "L1 block number mismatch"
    );
    ensure!(
        anchor_call._anchorStateRoot == taiko_data.l1_header.state_root,
        "L1 state root mismatch"
    );
    // The parent gas used input needs to match the gas used value of the parent block
    ensure!(
        anchor_call._parentGasUsed == taiko_data.parent_header.gas_used as u32,
        "parentGasUsed mismatch"
    );
    ensure!(
        anchor_call._baseFeeConfig.gasIssuancePerSecond
            == taiko_data.base_fee_config.gas_issuance_per_second,
        "gas issuance per second mismatch"
    );
    ensure!(
        anchor_call._baseFeeConfig.adjustmentQuotient
            == taiko_data.base_fee_config.adjustment_quotient,
        "basefee adjustment quotient mismatch"
    );
    ensure!(
        anchor_call._baseFeeConfig.sharingPctg == taiko_data.base_fee_config.sharing_pctg,
        "basefee ratio mismatch"
    );
    ensure!(
        anchor_call._baseFeeConfig.minGasExcess == taiko_data.base_fee_config.min_gas_excess,
        "min gas excess mismatch"
    );
    ensure!(
        anchor_call._baseFeeConfig.maxGasIssuancePerBlock
            == taiko_data.base_fee_config.max_gas_issuance_per_block,
        "max gas issuance per block mismatch"
    );

    Ok(())
}

// /// Verifies the anchor tx correctness based on the spec id
// pub fn check_anchor_tx_by_spec_id(
//     spec_id: SpecId,
//     transaction: &TransactionSigned,
//     sender: &Address,
//     block: &RecoveredBlock<Block>,
//     taiko_data: TaikoData,
// ) -> Result<()> {
//     if spec_id.is_enabled_in(SpecId::PACAYA) {
//         check_anchor_tx_pacaya(transaction, sender, &block, taiko_data)?;
//     } else if spec_id.is_enabled_in(SpecId::ONTAKE) {
//         check_anchor_tx_ontake(transaction, sender, &block, taiko_data)?;
//     } else if spec_id.is_enabled_in(SpecId::HEKLA) {
//         check_anchor_tx(transaction, sender, &block, taiko_data)?;
//     } else {
//         return Err(anyhow!("unknown spec id for anchor"));
//     }

//     Ok(())
// }
