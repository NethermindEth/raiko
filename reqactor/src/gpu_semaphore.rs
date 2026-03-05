use async_channel::{Receiver, Sender};

/// RAII guard that automatically releases the GPU slot when dropped.
/// This combines both concurrency control and GPU number assignment.
pub(crate) struct GpuPermit {
    /// The GPU number assigned to this permit
    gpu_number: u32,
    /// Channel sender to return the GPU number when dropped
    return_channel: Sender<u32>,
}

impl GpuPermit {
    /// Get the GPU number if one was assigned
    pub fn gpu_number(&self) -> u32 {
        self.gpu_number
    }
}

impl Drop for GpuPermit {
    fn drop(&mut self) {
        let gpu_number = self.gpu_number;
        let return_channel = self.return_channel.clone();

        tracing::trace!(
            "GPU RELEASE: Releasing GPU number {} back to pool",
            gpu_number
        );

        // Use send_blocking to ensure the GPU is returned even in Drop
        if let Err(e) = return_channel.send_blocking(gpu_number) {
            tracing::error!("Failed to return GPU {} to pool: {}", gpu_number, e);
        } else {
            tracing::trace!("Released GPU number {} back to pool", gpu_number);
        }
    }
}

/// A channel-based structure that controls concurrency AND assigns GPU numbers.
///
/// Uses a bounded channel to manage GPU number allocation.
/// Each acquired permit gets an exclusive GPU number from the channel (0..max_concurrency-1).
///
/// # Usage
/// ```ignore
/// let gpu_semaphore = Arc::new(GpuSemaphore::new(4)); // 4 GPUs available
/// let permit = gpu_semaphore.acquire().await;
/// let gpu_id = permit.gpu_number(); // 0..3
/// // GPU is automatically released when permit is dropped
/// ```
///
/// # Invariants
/// - The channel capacity ensures at most `max_concurrency` permits exist at any time
/// - Each permit gets a unique GPU number in range [0, max_concurrency)
/// - GPU numbers are reused in FIFO order after being released
#[derive(Clone)]
pub(crate) struct GpuSemaphore {
    /// Sender for returning GPU numbers to the pool
    tx: Sender<u32>,
    /// Receiver for acquiring GPU numbers from the pool (Clone-able, no Mutex needed!)
    rx: Receiver<u32>,
}

impl GpuSemaphore {
    /// Creates a new GPU semaphore with the specified maximum concurrency.
    ///
    /// # Arguments
    /// * `max_proving_concurrency` - The number of GPUs/slots available for parallel proving
    pub fn new(max_proving_concurrency: usize) -> Self {
        let (tx, rx) = async_channel::bounded::<u32>(max_proving_concurrency);

        // Pre-fill the channel with GPU numbers 0..max_proving_concurrency
        // We use try_send since the channel has the exact capacity we need
        for gpu_num in 0..max_proving_concurrency {
            tx.try_send(gpu_num as u32)
                .expect("Failed to initialize GPU pool - channel should have sufficient capacity");
        }

        Self { tx, rx }
    }

    /// Acquires a permit from the channel, waiting if necessary.
    /// Assigns an exclusive GPU number from the pool.
    ///
    /// Returns a `GpuPermit` that automatically releases the GPU number when dropped.
    ///
    /// # Panics
    /// Panics if the channel is unexpectedly closed.
    pub async fn acquire(&self) -> GpuPermit {
        // No Mutex needed! async_channel::Receiver is Clone and can be shared
        let gpu_number = self
            .rx
            .recv()
            .await
            .expect("GPU channel should not be closed");

        tracing::trace!("GPU ACQUIRE: Acquired GPU number {}", gpu_number);

        GpuPermit {
            gpu_number,
            return_channel: self.tx.clone(),
        }
    }
}

impl std::fmt::Debug for GpuSemaphore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GpuSemaphore")
            .field("tx", &"<Sender<u32>>")
            .field("rx", &"<Receiver<u32>>")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_gpu_semaphore() {
        let semaphore = GpuSemaphore::new(4);

        // Acquire a permit
        let permit1 = semaphore.acquire().await;
        let gpu1 = permit1.gpu_number();
        assert!(gpu1 < 4, "GPU number should be in range 0..4");

        // Acquire another permit
        let permit2 = semaphore.acquire().await;
        let gpu2 = permit2.gpu_number();
        assert_ne!(
            gpu1, gpu2,
            "Different permits should get different GPU numbers"
        );
        assert!(gpu2 < 4, "GPU number should be in range 0..4");

        // Drop first permit - GPU should be released and reusable
        drop(permit1);
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await; // Allow async drop to complete

        // Acquire a third permit - should get the released GPU
        let permit3 = semaphore.acquire().await;
        let gpu3 = permit3.gpu_number();
        assert!(gpu3 < 4, "GPU number should be in range 0..4");
    }

    #[tokio::test]
    async fn test_gpu_semaphore_concurrency_limit() {
        let semaphore = std::sync::Arc::new(GpuSemaphore::new(2));

        // Acquire 2 permits (should succeed immediately)
        let permit1 = semaphore.acquire().await;
        let permit2 = semaphore.acquire().await;

        assert!(permit1.gpu_number() < 2);
        assert!(permit2.gpu_number() < 2);
        assert_ne!(permit1.gpu_number(), permit2.gpu_number());

        // Try to acquire a third permit with a timeout - should block
        let semaphore_clone = semaphore.clone();
        let timeout_result = tokio::time::timeout(
            tokio::time::Duration::from_millis(50),
            semaphore_clone.acquire(),
        )
        .await;

        assert!(
            timeout_result.is_err(),
            "Should timeout when all GPUs are in use"
        );

        // Drop permits
        drop(permit1);
        drop(permit2);
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Now we should be able to acquire again
        let permit3 = semaphore.acquire().await;
        assert!(permit3.gpu_number() < 2);
    }

    #[tokio::test]
    async fn test_gpu_numbers_are_reused() {
        let semaphore = GpuSemaphore::new(2);

        // Acquire first GPU
        let permit1 = semaphore.acquire().await;
        let gpu1 = permit1.gpu_number();
        assert!(gpu1 < 2, "GPU should be 0 or 1");

        // Acquire second GPU
        let permit2 = semaphore.acquire().await;
        let gpu2 = permit2.gpu_number();
        assert!(gpu2 < 2, "GPU should be 0 or 1");
        assert_ne!(gpu1, gpu2, "Both GPUs should be different");

        // Release first GPU
        drop(permit1);
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Acquire again - should get the released GPU (FIFO)
        let permit3 = semaphore.acquire().await;
        let gpu3 = permit3.gpu_number();
        assert_eq!(
            gpu3, gpu1,
            "Should reuse the first released GPU in FIFO order"
        );

        // Release second GPU
        drop(permit2);
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Acquire again - should get the second released GPU
        let permit4 = semaphore.acquire().await;
        let gpu4 = permit4.gpu_number();
        assert_eq!(
            gpu4, gpu2,
            "Should reuse the second released GPU in FIFO order"
        );
    }
}
