//! Merkle tree implementation compatible with MurkyBase.sol
//!
//! This module provides a lazy, memory-efficient Merkle tree implementation that follows
//! the same algorithm as the Solidity MurkyBase contract, using sorted hash pairs for consistency.

use alloy::primitives::{B256, keccak256};

/// Maximum supported tree size to prevent overflow
#[cfg(target_pointer_width = "64")]
const MAX_TREE_SIZE: usize = 1 << 30;

#[cfg(target_pointer_width = "32")]
const MAX_TREE_SIZE: usize = 1 << 20;

/// A memory-efficient Merkle tree with lazy evaluation for low construction cost
///
/// This implementation combines the benefits of compact storage with lazy evaluation:
/// - Single allocation for memory efficiency
/// - Lazy computation of internal nodes
/// - Fast construction (just extends from iterator)
/// - On-demand computation of tree layers
///
/// # Solidity Compatibility
///
/// This implementation is fully compatible with MurkyBase.sol by using:
/// - Sorted hash pairs: `hash(min(a,b), max(a,b))`
/// - Zero-padding for odd-sized layers
/// - Left-to-right tree construction
#[derive(Debug, Clone)]
pub struct LazyMerkleTree {
    /// Single allocation containing all tree nodes
    nodes: Vec<B256>,
    /// Number of leaves in the tree
    leaf_count: usize,
    /// Whether the tree has been computed
    computed: bool,
    /// Cached height for efficiency
    height: usize,
    /// Pre-calculated layer sizes for optimization
    layer_sizes: Vec<usize>,
    /// Pre-calculated layer offsets for fast proof generation
    layer_offsets: Vec<usize>,
}

impl LazyMerkleTree {
    /// Create a lazy compact Merkle tree from leaves.
    ///
    /// leaf_count and leaves should match.
    pub fn from_leaves<I>(leaves: I, leaf_count: usize) -> Result<Self, MerkleError>
    where
        I: IntoIterator<Item = B256>,
    {
        let leaves_iter = leaves.into_iter();
        if leaf_count == 0 {
            return Err(MerkleError::EmptyTree);
        }

        // Validate tree size
        if leaf_count > MAX_TREE_SIZE {
            return Err(MerkleError::TooLarge);
        }

        // Correct height calculation: single leaf has height 0
        let height = log2_ceil(leaf_count);

        // Calculate layer sizes and total nodes
        let (layer_sizes, total_nodes) = Self::calculate_layer_sizes_and_total(leaf_count, height)?;

        // Pre-calculate layer offsets for fast proof generation
        let layer_offsets = Self::calculate_layer_offsets(&layer_sizes);

        // Efficient single allocation - initialize only what we need
        let mut nodes = Vec::with_capacity(total_nodes);
        nodes.extend(leaves_iter);
        nodes.resize(total_nodes, B256::ZERO);

        Ok(Self { nodes, leaf_count, computed: false, height, layer_sizes, layer_offsets })
    }

    /// Ensure the tree is computed (lazy evaluation)
    fn ensure_computed(&mut self) {
        if self.leaf_count <= 1 || self.computed {
            self.computed = true;
            return; // Nothing to compute for empty/single-leaf trees
        }

        // Reusable buffer for hashing - avoids allocation per hash
        let mut hash_buffer = [0u8; 64];

        // Compute offsets on-the-fly to save allocation
        let mut read_offset = 0;

        for layer in 0..self.height {
            let layer_size = self.layer_sizes[layer];
            let write_offset = read_offset + layer_size;

            // Process pairs in this layer
            let pairs = layer_size / 2;

            // Process complete pairs
            let mut idx = read_offset;
            for i in 0..pairs {
                let left = &self.nodes[idx];
                let right = &self.nodes[idx + 1];
                self.nodes[write_offset + i] = hash_leaf_pairs(left, right, &mut hash_buffer);
                idx += 2;
            }

            // Handle odd layer size
            if layer_size & 1 == 1 {
                let left = &self.nodes[read_offset + layer_size - 1];
                self.nodes[write_offset + pairs] =
                    hash_leaf_pairs(left, &B256::ZERO, &mut hash_buffer);
            }

            read_offset = write_offset;
        }

        self.computed = true;
    }

    /// Get the number of leaves
    #[inline]
    pub fn len(&self) -> usize {
        self.leaf_count
    }

    /// Check if empty
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.leaf_count == 0
    }

    /// Get the tree height
    #[inline]
    pub fn height(&self) -> usize {
        self.height
    }

    /// Get a reference to the leaves
    #[inline]
    pub fn leaves(&self) -> &[B256] {
        &self.nodes[..self.leaf_count]
    }

    /// Get the Merkle root (computed on first access)
    pub fn root(&mut self) -> Result<B256, MerkleError> {
        if self.leaf_count == 0 {
            return Err(MerkleError::EmptyTree);
        }

        if self.leaf_count == 1 {
            return Ok(self.nodes[0]);
        }

        self.ensure_computed();

        // Root is always the last node in our compact representation
        Ok(self.nodes[self.nodes.len() - 1])
    }

    /// Generate a Merkle proof
    pub fn proof(&mut self, index: usize) -> Result<Vec<B256>, MerkleError> {
        if self.leaf_count == 0 {
            return Err(MerkleError::EmptyTree);
        }

        if index >= self.leaf_count {
            return Err(MerkleError::IndexOutOfBounds { index, tree_size: self.leaf_count });
        }

        if self.leaf_count == 1 {
            return Err(MerkleError::SingleLeaf);
        }

        self.ensure_computed();

        let mut proof = Vec::with_capacity(self.height);
        let mut current_index = index;

        for layer in 0..self.height {
            let layer_size = self.layer_sizes[layer];
            let layer_offset = self.layer_offsets[layer];

            // Find sibling using XOR - flips LSB (even->odd, odd->even)
            // This gives us the sibling index in a binary tree efficiently
            let sibling_index = current_index ^ 1;

            let sibling = if sibling_index < layer_size {
                self.nodes[layer_offset + sibling_index]
            } else {
                B256::ZERO
            };

            proof.push(sibling);

            // Move to next layer
            current_index /= 2;
        }

        Ok(proof)
    }

    /// Verify a Merkle proof
    #[inline]
    pub fn verify_proof(root: &B256, proof: &[B256], leaf: &B256) -> bool {
        let mut rolling_hash = *leaf;
        let mut hash_buffer = [0u8; 64];

        for &sibling in proof {
            rolling_hash = hash_leaf_pairs(&rolling_hash, &sibling, &mut hash_buffer);
        }

        *root == rolling_hash
    }

    /// Calculate layer offsets from layer sizes
    fn calculate_layer_offsets(layer_sizes: &[usize]) -> Vec<usize> {
        let mut offsets = Vec::with_capacity(layer_sizes.len());
        let mut offset = 0;

        for &size in layer_sizes {
            offsets.push(offset);
            offset += size;
        }

        offsets
    }

    /// Calculate layer sizes and total nodes needed
    ///
    /// Note: We exclude the final root layer (size=1) from layer_sizes because:
    /// - It's always size 1 and doesn't need iteration
    /// - This saves a bounds check in the main computation loop
    /// - The root is always at nodes[nodes.len() - 1]
    fn calculate_layer_sizes_and_total(
        leaf_count: usize,
        height: usize,
    ) -> Result<(Vec<usize>, usize), MerkleError> {
        let mut layer_sizes = Vec::with_capacity(height);
        let mut current_size = leaf_count;
        let mut total_nodes = current_size;
        layer_sizes.push(current_size);

        for _ in 0..height {
            current_size = current_size.div_ceil(2);
            total_nodes = total_nodes.saturating_add(current_size);
            if total_nodes > MAX_TREE_SIZE * 2 {
                return Err(MerkleError::SizeCalculationOverflow);
            }
            // Exclude the final root layer to optimize iteration
            if current_size > 1 {
                layer_sizes.push(current_size);
            }
        }

        Ok((layer_sizes, total_nodes))
    }
}

/// Hash two leaf nodes together using the sorted approach from Merkle.sol
#[inline(always)]
fn hash_leaf_pairs(left: &B256, right: &B256, buffer: &mut [u8; 64]) -> B256 {
    // Sort the pair in ascending order before hashing
    let (first, second) = if left < right { (left, right) } else { (right, left) };

    // Concatenate and hash
    buffer[..32].copy_from_slice(first.as_ref());
    buffer[32..].copy_from_slice(second.as_ref());

    keccak256(buffer)
}

/// Calculate the ceiling of log2(x)
#[inline]
fn log2_ceil(x: usize) -> usize {
    match x {
        0 | 1 => 0,
        _ => (x - 1).ilog2() as usize + 1,
    }
}

/// Errors that can occur during Merkle tree operations
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree() {
        assert!(LazyMerkleTree::from_leaves(vec![], 0).is_err());
    }

    #[test]
    fn test_single_leaf_tree() {
        let leaf = B256::from([42u8; 32]);
        let mut tree = LazyMerkleTree::from_leaves(vec![leaf], 1).unwrap();

        assert_eq!(tree.root(), Ok(leaf));
        assert_eq!(tree.len(), 1);
        assert!(!tree.is_empty());
        assert_eq!(tree.proof(0), Err(MerkleError::SingleLeaf));
    }

    #[test]
    fn test_log2_ceil() {
        assert_eq!(log2_ceil(0), 0);
        assert_eq!(log2_ceil(1), 0);
        assert_eq!(log2_ceil(2), 1);
        assert_eq!(log2_ceil(3), 2);
        assert_eq!(log2_ceil(4), 2);
        assert_eq!(log2_ceil(5), 3);
        assert_eq!(log2_ceil(8), 3);
        assert_eq!(log2_ceil(9), 4);
        assert_eq!(log2_ceil(16), 4);
        assert_eq!(log2_ceil(17), 5);
    }

    #[test]
    fn test_error_handling() {
        // Test index out of bounds
        let mut tree =
            LazyMerkleTree::from_leaves(vec![B256::from([1u8; 32]), B256::from([2u8; 32])], 2)
                .unwrap();

        match tree.proof(5) {
            Err(MerkleError::IndexOutOfBounds { index, tree_size }) => {
                assert_eq!(index, 5);
                assert_eq!(tree_size, 2);
            }
            _ => panic!("Expected IndexOutOfBounds error"),
        }
    }
}
