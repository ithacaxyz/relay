//! Batch operations for multiple intents with merkle tree support.

use super::{Intent, SignedCalls};
use crate::{
    error::{IntentError, MerkleError},
    types::LazyMerkleTree,
};
use alloy::{
    primitives::{Address, B256},
    providers::DynProvider,
};
use futures_util::future::try_join_all;

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
    cached_tree: Option<LazyMerkleTree>,
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
    pub async fn compute_leaf_hashes(&self) -> Result<Vec<B256>, IntentError> {
        Ok(try_join_all(self.intents.iter().map(|(intent, provider, orchestrator_address)| {
            intent.compute_eip712_data(*orchestrator_address, provider)
        }))
        .await
        .map_err(|e| IntentError::from(MerkleError::LeafHashError(e.to_string())))?
        .into_iter()
        .map(|(hash, _)| hash)
        .collect())
    }

    /// Gets or computes the cached tree and leaves.
    async fn get_or_compute_tree(&mut self) -> Result<&mut LazyMerkleTree, IntentError> {
        // Check if we have a valid cache for this orchestrator
        if self.cached_tree.is_none() {
            let leaves = self.compute_leaf_hashes().await?;
            let leaves_count = leaves.len();
            let tree =
                LazyMerkleTree::from_leaves(leaves, leaves_count).map_err(IntentError::from)?;
            self.cached_tree = Some(tree);
        }

        Ok(self.cached_tree.as_mut().expect("cache should exist"))
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
    pub async fn root(&mut self) -> Result<B256, IntentError> {
        if self.intents.is_empty() {
            return Ok(B256::ZERO);
        }

        let tree = self.get_or_compute_tree().await?;

        tree.root().map_err(IntentError::from)
    }

    /// Gets a merkle proof for the intent at the given index.
    ///
    /// Returns an error if the index is out of bounds.
    ///
    /// The proof can be used to verify that a specific intent is included in
    /// the batch without needing to know all other intents. This is useful for
    /// on-chain verification where gas costs need to be minimized.
    pub async fn get_proof(&mut self, index: usize) -> Result<Vec<B256>, IntentError> {
        if index >= self.intents.len() {
            return Err(
                MerkleError::IndexOutOfBounds { index, tree_size: self.intents.len() }.into()
            );
        }

        self.get_or_compute_tree().await?.proof(index).map_err(IntentError::from)
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
