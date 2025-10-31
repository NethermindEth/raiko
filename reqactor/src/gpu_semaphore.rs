use std::{collections::VecDeque, sync::Arc};

use tokio::sync::{Mutex, Semaphore, SemaphorePermit};

/// RAII guard that automatically releases the GPU slot when dropped.
/// This combines both semaphore permit and GPU number assignment.
pub(crate) struct GpuPermit<'a> {
    /// The GPU number assigned to this permit (None if GPU not needed for this proof type)
    gpu_number: u32,
    /// The semaphore permit ensuring concurrency control
    _permit: SemaphorePermit<'a>,
    /// Reference to the GPU pool for releasing the GPU number
    gpu_pool: Arc<Mutex<VecDeque<u32>>>,
}

impl<'a> GpuPermit<'a> {
    /// Get the GPU number if one was assigned
    pub fn gpu_number(&self) -> u32 {
        self.gpu_number
    }
}

impl<'a> Drop for GpuPermit<'a> {
    fn drop(&mut self) {
        let gpu_pool = self.gpu_pool.clone();
        let gpu_number = self.gpu_number;
        // Spawn a task to release the GPU number asynchronously
        // Note: This is a best-effort release. If the tokio runtime is shutting down,
        // the release might not complete, but that's acceptable since the program is ending.
        tokio::spawn(async move {
            let mut pool = gpu_pool.lock().await;
            pool.push_back(gpu_number);
            tracing::trace!("Released GPU number {} back to pool", gpu_number);
        });
        // _permit is automatically dropped here, releasing the semaphore
    }
}

/// A semaphore-like structure that controls concurrency AND assigns GPU numbers.
///
/// This combines the functionality of `tokio::sync::Semaphore` with GPU number assignment.
/// Each acquired permit gets an exclusive GPU number from the pool (0..max_concurrency-1).
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
/// - The semaphore ensures at most `max_concurrency` permits exist at any time
/// - Each permit gets a unique GPU number in range [0, max_concurrency)
/// - GPU numbers are reused in FIFO order after being released
#[derive(Debug)]
pub(crate) struct GpuSemaphore {
    /// Controls overall concurrency limit
    semaphore: Semaphore,
    /// Pool of available GPU numbers
    gpu_pool: Arc<Mutex<VecDeque<u32>>>,
}

impl GpuSemaphore {
    /// Creates a new GPU semaphore with the specified maximum concurrency.
    ///
    /// # Arguments
    /// * `max_proving_concurrency` - The number of GPUs/slots available for parallel proving
    pub fn new(max_proving_concurrency: usize) -> Self {
        Self {
            semaphore: Semaphore::new(max_proving_concurrency),
            gpu_pool: Arc::new(Mutex::new(
                (0..max_proving_concurrency)
                    .map(|x| x as u32)
                    .collect::<VecDeque<u32>>(),
            )),
        }
    }

    /// Acquires a permit from the semaphore, waiting if necessary.
    /// For SP1 proof type, also assigns an exclusive GPU number.
    /// For other proof types, only controls concurrency without GPU assignment.
    ///
    /// Returns a `GpuPermit` that automatically releases both the semaphore permit
    /// and the GPU number (if assigned) when dropped.
    ///
    /// # Panics
    /// Panics if a GPU number is needed but the pool is unexpectedly empty.
    /// This should never happen as the semaphore guarantees the correct concurrency limit.
    pub async fn acquire(&self) -> GpuPermit<'_> {
        // First, acquire the semaphore permit (this limits overall concurrency)
        let permit = self
            .semaphore
            .acquire()
            .await
            .expect("Semaphore should not be closed");

        // Only allocate GPU for proof types that need it (currently just SP1)
        let mut pool = self.gpu_pool.lock().await;
        let gpu_num = pool.pop_front().unwrap_or_else(|| {
            panic!(
                "GPU pool exhausted! This should never happen. \
                         Available: {}, Semaphore permits: {}",
                pool.len(),
                self.semaphore.available_permits()
            )
        });

        tracing::debug!(
            "Acquired GPU permit with GPU number {gpu_num}, remaining GPUs: {}",
            pool.len()
        );

        let gpu_number = gpu_num;

        GpuPermit {
            gpu_number,
            _permit: permit,
            gpu_pool: self.gpu_pool.clone(),
        }
    }

    /// Returns the number of available permits in the semaphore.
    /// Useful for monitoring and debugging.
    #[allow(dead_code)]
    pub fn available_permits(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Returns the current number of available (unallocated) GPUs.
    #[allow(dead_code)]
    pub async fn available_gpus(&self) -> usize {
        self.gpu_pool.lock().await.len()
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
        assert!(gpu1 < 4);
        assert_eq!(semaphore.available_permits(), 3);
        assert_eq!(semaphore.available_gpus().await, 3);

        // Acquire another permit
        let permit2 = semaphore.acquire().await;
        let gpu2 = permit2.gpu_number();
        assert_ne!(gpu1, gpu2); // Different GPU numbers
        assert_eq!(semaphore.available_permits(), 2);

        // Drop first permit - GPU and semaphore slot should be released
        drop(permit1);
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await; // Allow async drop to complete
        assert_eq!(semaphore.available_permits(), 3);
        assert_eq!(semaphore.available_gpus().await, 3);
    }

    #[tokio::test]
    async fn test_gpu_semaphore_concurrency_limit() {
        let semaphore = std::sync::Arc::new(GpuSemaphore::new(2));

        // Acquire 2 permits (should succeed immediately)
        {
            let _permit1 = semaphore.acquire().await;
            let _permit2 = semaphore.acquire().await;
            assert_eq!(semaphore.available_permits(), 0);
            assert_eq!(semaphore.available_gpus().await, 0);
            // Permits dropped here
        }

        // After permits are dropped, should be available again
        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
        assert_eq!(semaphore.available_permits(), 2);
        assert_eq!(semaphore.available_gpus().await, 2);
    }

    #[tokio::test]
    async fn test_gpu_numbers_are_reused() {
        let semaphore = GpuSemaphore::new(3);

        let gpu1 = {
            let permit = semaphore.acquire().await;
            permit.gpu_number()
        };

        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;

        // After releasing, the same GPU number should be available again
        let permit = semaphore.acquire().await;
        let gpu2 = permit.gpu_number();

        // Should get one of the GPUs back (FIFO order means we get gpu1 back)
        assert_eq!(gpu1, gpu2);
    }
}
