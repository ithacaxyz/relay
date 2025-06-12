//! Batch operations for multiple intents with merkle tree support.

use super::{Intent, SignedCalls};
use alloy::{
    primitives::{Address, B256},
    providers::DynProvider,
};
use alloy_merkle_tree::tree::{MerkleProof, MerkleTree};
use futures_util::future::try_join_all;

/// Cached merkle tree data.
#[derive(Debug)]
struct TreeCache {
    tree: MerkleTree,
    leaves: Vec<B256>,
}

/// A wrapper for multiple intents that provides merkle tree operations.
///
/// This struct enables efficient verification of intent batches on-chain by
/// providing merkle root calculation and proof generation for a list of intents.
///
/// The merkle tree is cached after first computation for efficiency.
#[derive(Debug)]
pub struct Intents {
    /// Intents with respective provider and orchestrator address
    intents: Vec<(Intent, DynProvider, Address)>,
    cached_tree: Option<TreeCache>,
}

impl Intents {
    /// Creates a new `Intents` collection from a vector of intents and matching providers &
    /// orchestrator addresses.
    ///
    /// The order of intents is preserved as provided.
    pub fn new(intents: Vec<(Intent, DynProvider, Address)>) -> Self {
        Self { intents, cached_tree: None }
    }

    /// Computes EIP-712 signing hashes for all intents.
    async fn compute_leaf_hashes(&self) -> eyre::Result<Vec<B256>> {
        Ok(try_join_all(self.intents.iter().map(|(intent, provider, orchestrator_address)| {
            intent.compute_eip712_data(*orchestrator_address, provider)
        }))
        .await?
        .into_iter()
        .map(|(hash, _)| hash)
        .collect())
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
    async fn get_or_compute_tree(&mut self) -> eyre::Result<&TreeCache> {
        // Check if we have a valid cache for this orchestrator
        if self.cached_tree.is_none() {
            let leaves = self.compute_leaf_hashes().await?;
            self.cached_tree =
                Some(TreeCache { tree: Self::build_tree(leaves.iter().copied()), leaves });
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
    pub async fn root(&mut self) -> eyre::Result<B256> {
        if self.intents.is_empty() {
            return Ok(B256::ZERO);
        }

        Ok(self.get_or_compute_tree().await?.tree.root)
    }

    /// Gets a merkle proof for the intent at the given index.
    ///
    /// Returns `None` if the index is out of bounds.
    ///
    /// The proof can be used to verify that a specific intent is included in
    /// the batch without needing to know all other intents. This is useful for
    /// on-chain verification where gas costs need to be minimized.
    pub async fn get_proof(&mut self, index: usize) -> eyre::Result<Option<MerkleProof>> {
        if index >= self.intents.len() {
            return Ok(None);
        }

        let cache = self.get_or_compute_tree().await?;
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
}
