//! Merkle tree error types.

use thiserror::Error;

/// Errors that can occur during Merkle tree operations
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MerkleError {
    /// Cannot generate proof for empty tree
    #[error("Cannot operate on empty tree")]
    EmptyTree,
    /// Leaf index out of bounds
    #[error("Leaf index {index} out of bounds (tree has {tree_size} leaves)")]
    IndexOutOfBounds {
        /// The index that was requested
        index: usize,
        /// The actual size of the tree
        tree_size: usize,
    },
    /// Cannot generate proof for single leaf tree
    #[error("Cannot generate proof for single leaf tree")]
    SingleLeaf,
    /// Exceeds maximum supported size
    #[error("Exceeds maximum supported size")]
    TooLarge,
    /// Tree size calculation overflow
    #[error("Tree size calculation overflow")]
    SizeCalculationOverflow,
    /// Failed to compute leaf hashes
    #[error("Failed to compute leaf hashes: {0}")]
    LeafHashError(String),
}
