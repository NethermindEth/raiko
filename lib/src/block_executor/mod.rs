//! This module provides a block executor that wraps around a [`BlockExecutor`]
//! and adds an `is_optimistic` flag to indicate whether the execution is optimistic or not.
//! It is used for Raiko proofs and delegates all methods except `execute_block` to the inner executor.
//!
use core::ops::Deref;

use reth_evm::{
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockExecutorFactory,
        BlockExecutorFor, BlockValidationError, CommitChanges, ExecutableTx,
    },
    execute::Executor,
    ConfigureEvm, Database, EvmFactory, OnStateHook,
};
use reth_primitives::{NodePrimitives, RecoveredBlock};
use reth_revm::{db::states::bundle_state::BundleRetention, State};
use revm::{context::result::ExecutionResult, Inspector};
use tracing::warn;

use l1sload_inspector::L1SloadInspector;

mod l1sload_inspector;

/// A wrapper around any [`BlockExecutor`] that adds an `is_optimistic` flag to indicate whether
/// the execution is optimistic or not for Raiko proofs.
/// Except for execute_block, all methods are delegated to the inner executor.
struct BlockExecutorWithOptimistic<BE> {
    pub inner: BE,
    pub is_optimistic: bool,
}

impl<BE> Deref for BlockExecutorWithOptimistic<BE> {
    type Target = BE;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<BE> BlockExecutorWithOptimistic<BE> {
    pub fn new(inner: BE, is_optimistic: bool) -> Self {
        Self {
            inner,
            is_optimistic,
        }
    }
}

impl<BE> BlockExecutor for BlockExecutorWithOptimistic<BE>
where
    BE: BlockExecutor,
{
    type Transaction = BE::Transaction;

    type Receipt = BE::Receipt;

    type Evm = BE::Evm;

    /// Executes block with optimistic execution, if set
    fn execute_block(
        mut self,
        transactions: impl IntoIterator<Item = impl ExecutableTx<Self>>,
    ) -> Result<BlockExecutionResult<Self::Receipt>, BlockExecutionError>
    where
        Self: Sized,
    {
        // If not optimistic, delegate to inner executor
        if !self.is_optimistic {
            return self.inner.execute_block(transactions);
        }

        self.apply_pre_execution_changes()?;

        // All transactions are executed in a loop with optimistic handling
        for (i, tx) in transactions.into_iter().enumerate() {
            let is_anchor = i == 0;
            let res = self.execute_transaction(tx);

            if let Err(e) = res {
                if self.is_optimistic {
                    // If the execution is optimistic, we can skip the error and continue.
                    continue;
                }

                if is_anchor {
                    // If not optimistic, anchor transaction should not fail.
                    return Err(e);
                }

                // Only continue for invalid tx errors, not db errors (because those can be
                // manipulated by the prover)
                if let BlockExecutionError::Validation(err) = &e {
                    if let BlockValidationError::InvalidTx { hash, error } = err {
                        warn!("Invalid tx at {}: {:?}", hash, error);
                        continue;
                    }
                }

                // Any other type of error is not allowed
                return Err(e);
            }
        }

        self.apply_post_execution_changes()
    }

    fn apply_pre_execution_changes(&mut self) -> Result<(), BlockExecutionError> {
        self.inner.apply_pre_execution_changes()
    }

    fn execute_transaction_with_commit_condition(
        &mut self,
        tx: impl ExecutableTx<Self>,
        f: impl FnOnce(&ExecutionResult<<Self::Evm as reth_evm::Evm>::HaltReason>) -> CommitChanges,
    ) -> Result<Option<u64>, BlockExecutionError> {
        self.inner.execute_transaction_with_commit_condition(tx, f)
    }

    fn finish(
        self,
    ) -> Result<
        (
            Self::Evm,
            reth_evm::block::BlockExecutionResult<Self::Receipt>,
        ),
        BlockExecutionError,
    > {
        self.inner.finish()
    }

    fn set_state_hook(&mut self, hook: Option<Box<dyn reth_evm::OnStateHook>>) {
        self.inner.set_state_hook(hook)
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }
}

/// A generic block executor that uses a [`BlockExecutor`] to
/// execute blocks.
#[expect(missing_debug_implementations)]
pub struct TaikoWithOptimisticBlockExecutor<F, DB> {
    pub strategy_factory: F,
    pub db: State<DB>,
    pub is_optimistic: bool,
}

impl<F, DB> TaikoWithOptimisticBlockExecutor<F, DB>
where
    DB: Database,
{
    /// Creates a new `BasicBlockExecutor` with the given strategy.
    pub fn new(strategy_factory: F, db: DB, is_optimistic: bool) -> Self {
        let db = State::builder()
            .with_database(db)
            .with_bundle_update()
            .without_state_clear()
            .build();
        Self {
            strategy_factory,
            db,
            is_optimistic,
        }
    }
}

impl<'a, F, DB> TaikoWithOptimisticBlockExecutor<F, DB>
where
    DB: Database,
    F: ConfigureEvm,
{
    /// Creates a block executor with inspector for the given block.
    //
    // Note, ConfigureEvm ('self.strategy_factory') doesn't have build in
    // method for creating block_executor with inspector in evm, so we create it manually here.
    fn create_block_executor_with_inspector<I>(
        &'a mut self,
        block: &'a RecoveredBlock<<F::Primitives as NodePrimitives>::Block>,
        inspector: I,
    ) -> impl BlockExecutorFor<'a, F::BlockExecutorFactory, DB, I>
    where
    I: Inspector<
            <<F::BlockExecutorFactory as BlockExecutorFactory>::EvmFactory as EvmFactory>::Context<
                &'a mut State<DB>,
            >,
        > + 'a,
    {
        let evm_env = self.strategy_factory.evm_env(block.header());
        let evm =
            self.strategy_factory
                .evm_with_env_and_inspector(&mut self.db, evm_env, inspector);
        let ctx = self.strategy_factory.context_for_block(block);
        self.strategy_factory.create_executor(evm, ctx)
    }
}

impl<F, DB> Executor<DB> for TaikoWithOptimisticBlockExecutor<F, DB>
where
    F: ConfigureEvm,
    DB: Database,
{
    type Primitives = F::Primitives;
    type Error = BlockExecutionError;

    fn execute_one(
        &mut self,
        block: &RecoveredBlock<<Self::Primitives as NodePrimitives>::Block>,
    ) -> Result<BlockExecutionResult<<Self::Primitives as NodePrimitives>::Receipt>, Self::Error>
    {
        let is_optimistic = self.is_optimistic;
        let block_executor = self.create_block_executor_with_inspector(block, L1SloadInspector);

        let block_executor_with_optimistic =
            BlockExecutorWithOptimistic::new(block_executor, is_optimistic);

        let result =
            block_executor_with_optimistic.execute_block(block.transactions_recovered())?;

        self.db.merge_transitions(BundleRetention::Reverts);

        Ok(result)
    }

    fn execute_one_with_state_hook<H>(
        &mut self,
        block: &RecoveredBlock<<Self::Primitives as NodePrimitives>::Block>,
        state_hook: H,
    ) -> Result<BlockExecutionResult<<Self::Primitives as NodePrimitives>::Receipt>, Self::Error>
    where
        H: OnStateHook + 'static,
    {
        let is_optimistic = self.is_optimistic;
        let block_executor = self.create_block_executor_with_inspector(block, L1SloadInspector);

        let mut block_executor_with_optimistic =
            BlockExecutorWithOptimistic::new(block_executor, is_optimistic);

        block_executor_with_optimistic.set_state_hook(Some(Box::new(state_hook)));

        let result =
            block_executor_with_optimistic.execute_block(block.transactions_recovered())?;

        self.db.merge_transitions(BundleRetention::Reverts);

        Ok(result)
    }

    fn into_state(self) -> State<DB> {
        self.db
    }

    fn size_hint(&self) -> usize {
        self.db.bundle_state.size_hint()
    }
}
