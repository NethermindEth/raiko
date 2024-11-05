use std::sync::Arc;

use reth_chainspec::ChainSpec;
use reth_evm::{ConfigureEvm, ConfigureEvmEnv};
use reth_primitives::{
    revm::{config::revm_spec, env::fill_tx_env},
    revm_primitives::{AnalysisKind, CfgEnvWithHandlerCfg, TxEnv},
    Address, Head, Header, TransactionSigned, U256,
};
use reth_evm::{
    Database, EvmBuilder,
    taiko::handler_register,
    handler::register::EvmHandler,
    precompile::{PrecompileSpecId, secp256r1},
    ContextPrecompiles,
};

#[derive(Debug, Clone, Copy, Default)]
#[non_exhaustive]
pub struct CustomEthEvmConfig;

impl CustomEthEvmConfig {
    /// Sets the precompiles to the EVM handler
    ///
    /// This will be invoked when the EVM is created via [ConfigureEvm::evm] or
    /// [ConfigureEvm::evm_with_inspector]
    ///
    /// This will use the default mainnet precompiles and add additional precompiles.
    fn set_precompiles<EXT, DB>(handler: &mut EvmHandler<'_, EXT, DB>)
    where
        DB: Database,
    {
        // first we need the evm spec id, which determines the precompiles
        let spec_id = handler.cfg.spec_id;

        // install the precompiles
        handler.pre_execution.load_precompiles = Arc::new(move || {
            let mut loaded_precompiles: ContextPrecompiles<DB> =
                ContextPrecompiles::new(PrecompileSpecId::from_spec_id(spec_id));

            loaded_precompiles.extend(secp256r1::precompiles());

            loaded_precompiles
        });
    }
}

impl ConfigureEvmEnv for CustomEthEvmConfig {
    fn fill_tx_env(tx_env: &mut TxEnv, transaction: &TransactionSigned, sender: Address) {
        fill_tx_env(tx_env, transaction, sender)
    }

    fn fill_cfg_env(
        cfg_env: &mut CfgEnvWithHandlerCfg,
        chain_spec: &ChainSpec,
        header: &Header,
        total_difficulty: U256,
    ) {
        let spec_id = revm_spec(
            chain_spec,
            Head {
                number: header.number,
                timestamp: header.timestamp,
                difficulty: header.difficulty,
                total_difficulty,
                hash: Default::default(),
            },
        );

        cfg_env.chain_id = chain_spec.chain().id();
        cfg_env.perf_analyse_created_bytecodes = AnalysisKind::Analyse;

        cfg_env.handler_cfg.spec_id = spec_id;
        cfg_env.handler_cfg.is_taiko = chain_spec.is_taiko();
    }
}

impl ConfigureEvm for CustomEthEvmConfig {
    type DefaultExternalContext<'a> = ();

    fn evm<'a, DB: Database + 'a>(
        &self,
        db: DB,
        is_taiko: bool,
    ) -> reth_evm::Evm<'a, Self::DefaultExternalContext<'a>, DB> {
        let builder = EvmBuilder::default().with_db(db);
        if is_taiko {
            builder.append_handler_register(handler_register::taiko_handle_register).build()
        } else {
            builder.build()
        }
    }
}

