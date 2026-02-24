//! This module provides a block executor that wraps around a [`BlockExecutor`]
//! and adds an `is_optimistic` flag to indicate whether the execution is optimistic or not.
//! It is used for Raiko proofs and delegates all methods except `execute_block` to the inner executor.
//!
use core::ops::Deref;

use alloy_consensus::TransactionEnvelope;
use reth_evm::{
    block::{
        BlockExecutionError, BlockExecutionResult, BlockExecutor, BlockValidationError,
        CommitChanges, ExecutableTx,
    },
    execute::Executor,
    ConfigureEvm, Database, Evm, OnStateHook,
};
use reth_primitives::{NodePrimitives, RecoveredBlock};
use reth_revm::{
    context::result::ExecutionResult, db::states::bundle_state::BundleRetention, State,
};
use tracing::warn;

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
    BE: BlockExecutor<Transaction: TransactionEnvelope>,
{
    type Transaction = BE::Transaction;

    type Receipt = BE::Receipt;

    type Evm = BE::Evm;

    type Result = BE::Result;

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
        f: impl FnOnce(&ExecutionResult<<Self::Evm as Evm>::HaltReason>) -> CommitChanges,
    ) -> Result<Option<u64>, BlockExecutionError> {
        self.inner.execute_transaction_with_commit_condition(tx, f)
    }

    fn finish(
        self,
    ) -> Result<(Self::Evm, BlockExecutionResult<Self::Receipt>), BlockExecutionError> {
        self.inner.finish()
    }

    fn set_state_hook(&mut self, hook: Option<Box<dyn OnStateHook>>) {
        self.inner.set_state_hook(hook)
    }

    fn evm_mut(&mut self) -> &mut Self::Evm {
        self.inner.evm_mut()
    }

    fn evm(&self) -> &Self::Evm {
        self.inner.evm()
    }

    fn receipts(&self) -> &[Self::Receipt] {
        self.inner.receipts()
    }

    fn execute_transaction_without_commit(
        &mut self,
        tx: impl ExecutableTx<Self>,
    ) -> Result<Self::Result, BlockExecutionError> {
        self.inner.execute_transaction_without_commit(tx)
    }

    fn commit_transaction(&mut self, output: Self::Result) -> Result<u64, BlockExecutionError> {
        self.inner.commit_transaction(output)
    }
}

/// A generic block executor that uses a [`BlockExecutor`] to
/// execute blocks.
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

impl<F, DB> Executor<DB> for TaikoWithOptimisticBlockExecutor<F, DB>
where
    F: ConfigureEvm,
    DB: Database,
    <<F as ConfigureEvm>::Primitives as NodePrimitives>::SignedTx: TransactionEnvelope,
{
    type Primitives = F::Primitives;
    type Error = BlockExecutionError;

    fn execute_one(
        &mut self,
        block: &RecoveredBlock<<Self::Primitives as NodePrimitives>::Block>,
    ) -> Result<BlockExecutionResult<<Self::Primitives as NodePrimitives>::Receipt>, Self::Error>
    {
        let block_executor = self
            .strategy_factory
            .executor_for_block(&mut self.db, block)
            .map_err(|e| BlockExecutionError::other(e))?;

        let block_executor_with_optimistic =
            BlockExecutorWithOptimistic::new(block_executor, self.is_optimistic);

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
        let block_executor = self
            .strategy_factory
            .executor_for_block(&mut self.db, block)
            .map_err(|e| BlockExecutionError::other(e))?;

        let mut block_executor_with_optimistic =
            BlockExecutorWithOptimistic::new(block_executor, self.is_optimistic);

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
