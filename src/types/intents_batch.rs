//! Batch operations for multiple intents with merkle tree support.

use super::{Intent, SignedCalls};
use alloy::{
    primitives::{Address, B256},
    providers::DynProvider,
};
use alloy_merkle_tree::tree::{MerkleProof, MerkleTree};
use futures_util::future::try_join_all;

/// Cached merkle tree data for a specific orchestrator.
#[derive(Debug)]
struct TreeCache {
    orchestrator: Address,
    tree: MerkleTree,
    leaves: Vec<B256>,
}

/// A wrapper for multiple intents that provides merkle tree operations.
///
/// This struct enables efficient verification of intent batches on-chain by
/// providing merkle root calculation and proof generation for a list of intents.
///
/// The merkle tree is cached after first computation for efficiency.
/// ```
#[derive(Debug)]
pub struct Intents {
    intents: Vec<Intent>,
    cached_tree: Option<TreeCache>,
}

impl Clone for Intents {
    fn clone(&self) -> Self {
        Self {
            intents: self.intents.clone(),
            cached_tree: None, // Don't clone the cache
        }
    }
}

impl Intents {
    /// Creates a new `Intents` collection from a vector of intents.
    ///
    /// The order of intents is preserved as provided.
    pub fn new(intents: Vec<Intent>) -> Self {
        Self { intents, cached_tree: None }
    }

    /// Computes EIP-712 signing hashes for all intents in parallel.
    async fn compute_leaf_hashes(
        &self,
        orchestrator_address: Address,
        provider: &DynProvider,
    ) -> eyre::Result<Vec<B256>> {
        let eip712_futures = self
            .intents
            .iter()
            .map(|intent| intent.compute_eip712_data(orchestrator_address, provider));

        let eip712_results = try_join_all(eip712_futures).await?;
        Ok(eip712_results.into_iter().map(|(hash, _)| hash).collect())
    }

    /// Builds a merkle tree from the given leaf hashes.
    fn build_tree(leaves: impl Iterator<Item = B256>) -> MerkleTree {
        let mut tree = MerkleTree::new();
        for leaf in leaves {
            tree.insert(leaf);
        }
        tree.finish();
        tree
    }

    /// Gets or computes the cached tree and leaves.
    async fn get_or_compute_tree(
        &mut self,
        orchestrator_address: Address,
        provider: &DynProvider,
    ) -> eyre::Result<&TreeCache> {
        // Check if we have a valid cache for this orchestrator
        let needs_compute = match &self.cached_tree {
            Some(cache) => cache.orchestrator != orchestrator_address,
            None => true,
        };

        if needs_compute {
            let leaves = self.compute_leaf_hashes(orchestrator_address, provider).await?;
            let tree = Self::build_tree(leaves.iter().copied());
            self.cached_tree = Some(TreeCache { orchestrator: orchestrator_address, tree, leaves });
        }

        Ok(self.cached_tree.as_ref().expect("cache should exist after computation"))
    }

    /// Returns the merkle root of all intents.
    ///
    /// The root is calculated by:
    /// 1. Computing the EIP-712 signing hash of each intent
    /// 2. Building a merkle tree from the hashes
    ///
    /// The leaf hashes are the EIP-712 signing hashes that would be signed by users,
    /// ensuring the merkle root represents the exact intents that were authorized.
    /// The tree is cached after first computation for efficiency.
    pub async fn root(
        &mut self,
        orchestrator_address: Address,
        provider: &DynProvider,
    ) -> eyre::Result<B256> {
        if self.intents.is_empty() {
            return Ok(B256::ZERO);
        }

        let cache = self.get_or_compute_tree(orchestrator_address, provider).await?;
        Ok(cache.tree.root)
    }

    /// Gets a merkle proof for the intent at the given index.
    ///
    /// Returns `None` if the index is out of bounds.
    ///
    /// The proof can be used to verify that a specific intent is included in
    /// the batch without needing to know all other intents. This is useful for
    /// on-chain verification where gas costs need to be minimized.
    pub async fn get_proof(
        &mut self,
        index: usize,
        orchestrator_address: Address,
        provider: &DynProvider,
    ) -> eyre::Result<Option<MerkleProof>> {
        if index >= self.intents.len() {
            return Ok(None);
        }

        let cache = self.get_or_compute_tree(orchestrator_address, provider).await?;
        Ok(cache.tree.create_proof(&cache.leaves[index]))
    }

    /// Returns the number of intents.
    pub fn len(&self) -> usize {
        self.intents.len()
    }

    /// Returns true if there are no intents.
    pub fn is_empty(&self) -> bool {
        self.intents.is_empty()
    }

    /// Returns a reference to the intent at the given index.
    pub fn get(&self, index: usize) -> Option<&Intent> {
        self.intents.get(index)
    }

    /// Returns an iterator over the intents.
    pub fn iter(&self) -> std::slice::Iter<'_, Intent> {
        self.intents.iter()
    }

    /// Returns the underlying vector of intents.
    pub fn into_inner(self) -> Vec<Intent> {
        self.intents
    }

    /// Returns a reference to the underlying vector of intents.
    pub fn as_slice(&self) -> &[Intent] {
        &self.intents
    }
}

impl From<Vec<Intent>> for Intents {
    fn from(intents: Vec<Intent>) -> Self {
        Self::new(intents)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::{Address, Bytes, U256, address, uint};

    fn create_test_intent(nonce: U256, payment_token: Address) -> Intent {
        Intent {
            eoa: address!("0000000000000000000000000000000000000001"),
            executionData: Bytes::default(),
            nonce,
            payer: Address::ZERO,
            paymentToken: payment_token,
            prePaymentMaxAmount: U256::ZERO,
            totalPaymentMaxAmount: U256::ZERO,
            combinedGas: U256::ZERO,
            encodedPreCalls: vec![],
            encodedFundTransfers: Bytes::default(),
            prePaymentAmount: U256::ZERO,
            totalPaymentAmount: U256::ZERO,
            paymentRecipient: Address::ZERO,
            signature: Bytes::default(),
            paymentSignature: Bytes::default(),
            supportedAccountImplementation: Address::ZERO,
        }
    }

    #[test]
    fn test_intents_construction() {
        let intents = Intents::new(vec![]);
        assert!(intents.is_empty());
        assert_eq!(intents.len(), 0);

        let intent1 =
            create_test_intent(uint!(1_U256), address!("0000000000000000000000000000000000000001"));
        let intent2 =
            create_test_intent(uint!(2_U256), address!("0000000000000000000000000000000000000002"));
        let intents = Intents::new(vec![intent1.clone(), intent2.clone()]);

        assert_eq!(intents.len(), 2);
        assert!(!intents.is_empty());
        assert_eq!(intents.get(0).expect("should have first intent").nonce, uint!(1_U256));
        assert_eq!(intents.get(1).expect("should have second intent").nonce, uint!(2_U256));
    }

    #[test]
    fn test_intents_preserve_order() {
        // Create intents with different payment tokens
        let intent1 =
            create_test_intent(uint!(1_U256), address!("0000000000000000000000000000000000000003"));
        let intent2 =
            create_test_intent(uint!(2_U256), address!("0000000000000000000000000000000000000001"));
        let intent3 =
            create_test_intent(uint!(3_U256), address!("0000000000000000000000000000000000000002"));

        // Create intents - order should be preserved
        let intents = Intents::new(vec![intent1.clone(), intent2.clone(), intent3.clone()]);

        // Verify order is preserved as provided
        assert_eq!(
            intents.get(0).expect("should have first intent").paymentToken,
            address!("0000000000000000000000000000000000000003")
        );
        assert_eq!(
            intents.get(1).expect("should have second intent").paymentToken,
            address!("0000000000000000000000000000000000000001")
        );
        assert_eq!(
            intents.get(2).expect("should have third intent").paymentToken,
            address!("0000000000000000000000000000000000000002")
        );
    }

    #[test]
    fn test_from_vec() {
        let intents_vec = vec![
            create_test_intent(uint!(1_U256), address!("0000000000000000000000000000000000000001")),
            create_test_intent(uint!(2_U256), address!("0000000000000000000000000000000000000002")),
        ];

        let intents: Intents = intents_vec.clone().into();
        assert_eq!(intents.len(), 2);
        assert_eq!(intents.as_slice(), &intents_vec[..]);
    }

    // Note: Integration tests with actual provider would require a running anvil instance
    // or mock provider setup, which is beyond the scope of this implementation.
    // The async methods (root, get_proof) should be tested in integration tests.
}
