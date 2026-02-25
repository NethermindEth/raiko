use raiko_reqpool::{RequestEntity, RequestKey};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashSet, VecDeque};

/// Wrapper that gives [`BinaryHeap`] min-heap behaviour keyed on `batch_id`.
///
/// Lower `batch_id` is popped first.
/// Rust's `BinaryHeap` is a *max*-heap, so we invert the comparison.
#[derive(Debug)]
struct PriorityItem {
    /// The batch_id / proposal_id used for ordering (lower = higher priority).
    sort_key: u64,
    request_key: RequestKey,
    request_entity: RequestEntity,
}

impl PartialEq for PriorityItem {
    fn eq(&self, other: &Self) -> bool {
        self.sort_key == other.sort_key
    }
}
impl Eq for PriorityItem {}

impl PartialOrd for PriorityItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PriorityItem {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse: lower sort_key = "greater" so BinaryHeap pops it first.
        other.sort_key.cmp(&self.sort_key)
    }
}

/// Queue of requests to be processed.
///
/// Priority tiers (highest first):
///   1. **Aggregation** — `Aggregation` and `ShastaAggregation`
///   2. **Batch / Shasta proof** — `BatchProof` and `ShastaProof`
///   3. **Preflight** — everything else (guest-input, single-proof, …)
///
/// Within tiers 1 and 2 each heap is ordered by ascending
/// `batch_id` / `proposal_id`, with FIFO tiebreaking, so lower IDs
/// are proved first.
#[derive(Debug)]
pub struct Queue {
    /// High priority: aggregation requests (min-heap by batch_id)
    agg_heap: BinaryHeap<PriorityItem>,
    /// Medium priority: batch/shasta proof requests (min-heap by batch_id)
    batch_heap: BinaryHeap<PriorityItem>,
    /// Low priority: preflight / single-proof requests (FIFO)
    preflight_queue: VecDeque<(RequestKey, RequestEntity)>,
    /// Requests that are currently being worked on
    working_in_progress: HashSet<RequestKey>,
    /// Requests that have been pushed to the queue or are in-flight
    queued_keys: HashSet<RequestKey>,
    /// Maximum number of requests that can be in the queue (including in-progress)
    max_queue_size: usize,
}

impl Queue {
    pub fn new(max_queue_size: usize) -> Self {
        Self {
            agg_heap: BinaryHeap::new(),
            batch_heap: BinaryHeap::new(),
            preflight_queue: VecDeque::new(),
            working_in_progress: HashSet::new(),
            queued_keys: HashSet::new(),
            max_queue_size,
        }
    }

    pub fn contains(&self, request_key: &RequestKey) -> bool {
        self.queued_keys.contains(request_key)
    }

    /// Check if the queue is empty (no pending requests)
    pub fn is_empty(&self) -> bool {
        self.agg_heap.is_empty() && self.batch_heap.is_empty() && self.preflight_queue.is_empty()
    }

    /// Check if the queue is at capacity
    pub fn is_at_capacity(&self) -> bool {
        self.queued_keys.len() >= self.max_queue_size
    }

    /// Get the current queue size (including in-progress requests)
    pub fn size(&self) -> usize {
        self.queued_keys.len()
    }

    /// Total number of pending items across all three tiers (excludes in-progress).
    pub fn pending_len(&self) -> usize {
        self.agg_heap.len() + self.batch_heap.len() + self.preflight_queue.len()
    }

    pub fn add_pending(
        &mut self,
        request_key: RequestKey,
        request_entity: RequestEntity,
    ) -> Result<(), String> {
        // Check if queue is at capacity
        if self.is_at_capacity() {
            return Err("Reached the maximum queue size, please try again later".to_string());
        }

        if self.queued_keys.insert(request_key.clone()) {
            match &request_key {
                // --- Tier 1: Aggregation (min-heap by batch_id / proposal_id) ---
                RequestKey::Aggregation(_) | RequestKey::ShastaAggregation(_) => {
                    let sort_key = request_key.batch_sort_key().unwrap_or(u64::MAX);
                    tracing::info!(sort_key, "Adding aggregation request to high priority heap");
                    self.agg_heap.push(PriorityItem {
                        sort_key,
                        request_key,
                        request_entity,
                    });
                }
                // --- Tier 2: Batch / Shasta proof (min-heap by batch_id / proposal_id) ---
                RequestKey::BatchProof(_) | RequestKey::ShastaProof(_) => {
                    let sort_key = request_key.batch_sort_key().unwrap_or(u64::MAX);
                    tracing::info!(
                        sort_key,
                        "Adding batch/shasta proof request to medium priority heap"
                    );
                    self.batch_heap.push(PriorityItem {
                        sort_key,
                        request_key,
                        request_entity,
                    });
                }
                // --- Tier 3: Preflight / single-proof / guest-input (FIFO) ---
                _ => {
                    self.preflight_queue
                        .push_back((request_key, request_entity));
                }
            }
        }
        Ok(())
    }

    /// Attempts to move a request from either the high, medium or low priority queue
    /// into the in-flight set and starts processing it.
    ///
    /// Order: all aggregations (lowest batch_id first) → all batch/shasta proofs
    /// (lowest batch_id first) → preflight (FIFO).
    pub fn try_next(&mut self) -> Option<(RequestKey, RequestEntity)> {
        let item = if !self.agg_heap.is_empty() {
            self.agg_heap.pop()
        } else if !self.batch_heap.is_empty() {
            self.batch_heap.pop()
        } else {
            return self.preflight_queue.pop_front().map(|(k, e)| {
                self.working_in_progress.insert(k.clone());
                (k, e)
            });
        };

        let PriorityItem {
            request_key,
            request_entity,
            ..
        } = item?;

        self.working_in_progress.insert(request_key.clone());
        Some((request_key, request_entity))
    }

    pub fn complete(&mut self, request_key: RequestKey) {
        self.working_in_progress.remove(&request_key);
        self.queued_keys.remove(&request_key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;
    use raiko_core::interfaces::ProverSpecificOpts;
    use raiko_lib::{input::BlobProofType, primitives::B256, proof_type::ProofType, prover::Proof};
    use raiko_reqpool::{
        AggregationRequestEntity, AggregationRequestKey, BatchProofRequestEntity,
        BatchProofRequestKey, SingleProofRequestEntity, SingleProofRequestKey,
    };
    use std::collections::HashMap;

    // ── helpers ──────────────────────────────────────────────────────────

    /// SingleProof → preflight tier
    fn make_single_proof_key(block_number: u64) -> RequestKey {
        RequestKey::SingleProof(SingleProofRequestKey::new(
            1u64,
            block_number,
            B256::from([1u8; 32]),
            ProofType::Native,
            "test_prover".to_string(),
        ))
    }

    fn make_single_proof_entity(block_number: u64) -> RequestEntity {
        RequestEntity::SingleProof(SingleProofRequestEntity::new(
            block_number,
            5678u64,
            "ethereum".to_string(),
            "ethereum".to_string(),
            B256::from([0u8; 32]),
            Address::ZERO,
            ProofType::Native,
            BlobProofType::ProofOfEquivalence,
            HashMap::new(),
        ))
    }

    /// Aggregation → agg tier, sort key = min(block_numbers)
    fn make_aggregation_key(block_numbers: Vec<u64>) -> RequestKey {
        RequestKey::Aggregation(AggregationRequestKey::new(ProofType::Native, block_numbers))
    }

    fn make_aggregation_entity(block_numbers: Vec<u64>) -> RequestEntity {
        RequestEntity::Aggregation(AggregationRequestEntity::new(
            block_numbers,
            vec![Proof::default()],
            ProofType::Native,
            ProverSpecificOpts::default(),
        ))
    }

    /// ShastaAggregation → agg tier, sort key = min(proposal_ids)
    fn make_shasta_agg_key(proposal_ids: Vec<u64>) -> RequestKey {
        RequestKey::ShastaAggregation(AggregationRequestKey::new(ProofType::Native, proposal_ids))
    }

    fn make_shasta_agg_entity(proposal_ids: Vec<u64>) -> RequestEntity {
        RequestEntity::ShastaAggregation(AggregationRequestEntity::new(
            proposal_ids,
            vec![Proof::default()],
            ProofType::Native,
            ProverSpecificOpts::default(),
        ))
    }

    /// BatchProof → batch tier, sort key = batch_id
    fn make_batch_proof_key(batch_id: u64) -> RequestKey {
        RequestKey::BatchProof(BatchProofRequestKey::new(
            1u64,
            batch_id,
            100u64,
            ProofType::Native,
            "prover".to_string(),
        ))
    }

    fn make_batch_proof_entity(batch_id: u64) -> RequestEntity {
        RequestEntity::BatchProof(BatchProofRequestEntity::new(
            batch_id,
            100u64,
            "ethereum".to_string(),
            "ethereum".to_string(),
            B256::from([0u8; 32]),
            Address::ZERO,
            ProofType::Native,
            BlobProofType::ProofOfEquivalence,
            HashMap::new(),
        ))
    }

    // ── tests ───────────────────────────────────────────────────────────

    /// Aggregation (high) before preflight (low); within agg tier sorted by
    /// ascending batch_id (min block_number).
    #[test]
    fn test_tier_priority_and_agg_sorted() {
        let mut queue = Queue::new(10);

        let low1 = make_single_proof_key(1);
        let low2 = make_single_proof_key(2);
        let high1 = make_aggregation_key(vec![100]); // sort key 100
        let high2 = make_aggregation_key(vec![200]); // sort key 200

        // Insert out of order: low, high(200), low, high(100)
        queue
            .add_pending(low1.clone(), make_single_proof_entity(1))
            .unwrap();
        queue
            .add_pending(high2.clone(), make_aggregation_entity(vec![200]))
            .unwrap();
        queue
            .add_pending(low2.clone(), make_single_proof_entity(2))
            .unwrap();
        queue
            .add_pending(high1.clone(), make_aggregation_entity(vec![100]))
            .unwrap();

        assert_eq!(queue.queued_keys.len(), 4);
        assert_eq!(queue.pending_len(), 4);

        // Tier 1 first, sorted ascending by batch_id (100 < 200)
        assert_eq!(queue.try_next().unwrap().0, high1);
        assert_eq!(queue.try_next().unwrap().0, high2);
        // Tier 3 (preflight) FIFO
        assert_eq!(queue.try_next().unwrap().0, low1);

        // Complete some
        queue.complete(high1);
        assert_eq!(queue.working_in_progress.len(), 2);

        assert_eq!(queue.try_next().unwrap().0, low2);

        queue.complete(high2);
        queue.complete(low1);
        queue.complete(low2);

        assert_eq!(queue.queued_keys.len(), 0);
        assert_eq!(queue.working_in_progress.len(), 0);
        assert!(queue.is_empty());
    }

    /// Full 3-tier ordering:
    ///   agg (batch_id 1) → agg (batch_id 2) → batch proof (batch_id 1) →
    ///   batch proof (batch_id 2) → preflight
    #[test]
    fn test_batch_id_ordering_across_tiers() {
        let mut queue = Queue::new(20);

        let preflight = make_single_proof_key(42);
        let batch2 = make_batch_proof_key(2);
        let batch1 = make_batch_proof_key(1);
        let agg2 = make_aggregation_key(vec![2]);
        let agg1 = make_aggregation_key(vec![1]);

        // Insert in completely scrambled order
        queue
            .add_pending(preflight.clone(), make_single_proof_entity(42))
            .unwrap();
        queue
            .add_pending(batch2.clone(), make_batch_proof_entity(2))
            .unwrap();
        queue
            .add_pending(agg2.clone(), make_aggregation_entity(vec![2]))
            .unwrap();
        queue
            .add_pending(batch1.clone(), make_batch_proof_entity(1))
            .unwrap();
        queue
            .add_pending(agg1.clone(), make_aggregation_entity(vec![1]))
            .unwrap();

        assert_eq!(queue.pending_len(), 5);

        // Expect: agg1, agg2, batch1, batch2, preflight
        assert_eq!(queue.try_next().unwrap().0, agg1);
        assert_eq!(queue.try_next().unwrap().0, agg2);
        assert_eq!(queue.try_next().unwrap().0, batch1);
        assert_eq!(queue.try_next().unwrap().0, batch2);
        assert_eq!(queue.try_next().unwrap().0, preflight);
        assert!(queue.try_next().is_none());
    }

    /// ShastaAggregation and ShastaProof (via BatchProof key) are routed to
    /// the correct tiers instead of falling to preflight.
    #[test]
    fn test_shasta_variants_routed_correctly() {
        let mut queue = Queue::new(20);

        let preflight = make_single_proof_key(1);
        let shasta_agg = make_shasta_agg_key(vec![10]);
        let batch_proof = make_batch_proof_key(5);

        queue
            .add_pending(preflight.clone(), make_single_proof_entity(1))
            .unwrap();
        queue
            .add_pending(batch_proof.clone(), make_batch_proof_entity(5))
            .unwrap();
        queue
            .add_pending(shasta_agg.clone(), make_shasta_agg_entity(vec![10]))
            .unwrap();

        // ShastaAgg → agg tier (first), BatchProof → batch tier (second), preflight last
        assert_eq!(queue.try_next().unwrap().0, shasta_agg);
        assert_eq!(queue.try_next().unwrap().0, batch_proof);
        assert_eq!(queue.try_next().unwrap().0, preflight);
    }

    /// Agg and ShastaAgg in the same tier, sorted together by batch_id.
    #[test]
    fn test_mixed_agg_and_shasta_agg_sorted() {
        let mut queue = Queue::new(20);

        let agg5 = make_aggregation_key(vec![5]);
        let shasta_agg3 = make_shasta_agg_key(vec![3]);
        let shasta_agg7 = make_shasta_agg_key(vec![7]);

        queue
            .add_pending(shasta_agg7.clone(), make_shasta_agg_entity(vec![7]))
            .unwrap();
        queue
            .add_pending(agg5.clone(), make_aggregation_entity(vec![5]))
            .unwrap();
        queue
            .add_pending(shasta_agg3.clone(), make_shasta_agg_entity(vec![3]))
            .unwrap();

        // Sorted ascending: 3, 5, 7
        assert_eq!(queue.try_next().unwrap().0, shasta_agg3);
        assert_eq!(queue.try_next().unwrap().0, agg5);
        assert_eq!(queue.try_next().unwrap().0, shasta_agg7);
    }

    #[test]
    fn test_queue_limit() {
        let mut queue = Queue::new(2);

        for i in 0..2 {
            let key = make_single_proof_key(i as u64);
            let entity = make_single_proof_entity(i as u64);
            assert!(queue.add_pending(key, entity).is_ok());
        }

        assert_eq!(queue.size(), 2);
        assert!(queue.is_at_capacity());

        let result = queue.add_pending(make_single_proof_key(3), make_single_proof_entity(3));
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Reached the maximum queue size, please try again later"
        );
        assert_eq!(queue.size(), 2);
    }
}
