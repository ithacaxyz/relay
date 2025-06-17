//! Test fixtures for Merkle tree implementations
//!
//! This module provides utilities for loading and using Merkle tree test fixtures
//! generated from the Solidity Murky implementation.

mod fixtures;

use alloy::primitives::B256;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// A single test case from the Merkle fixtures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTestCase {
    /// Name of the test case
    pub name: String,
    /// Expected Merkle root
    pub root: B256,
    /// Height of the tree
    pub height: usize,
    /// Leaf values
    pub leaves: Vec<B256>,
    /// Proofs for each leaf
    pub proofs: Vec<MerkleProof>,
}

/// A Merkle proof for a specific leaf
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Index of the leaf this proof is for
    pub index: usize,
    /// The leaf value
    pub leaf: B256,
    /// The proof path (siblings from leaf to root)
    pub proof: Vec<B256>,
}

/// Collection of Merkle test cases
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTestFixtures {
    /// All test cases
    pub test_cases: Vec<MerkleTestCase>,
}

impl MerkleTestFixtures {
    /// Load test fixtures from a JSON file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let fixtures: Self = serde_json::from_str(&content)?;
        Ok(fixtures)
    }

    /// Load the default Murky fixtures
    pub fn load_default() -> Result<Self, Box<dyn std::error::Error>> {
        let fixture_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/merkle/merkle_murky_fixtures.json"
        );
        Self::load_from_file(fixture_path)
    }

    /// Get all test cases
    pub fn test_cases(&self) -> &[MerkleTestCase] {
        &self.test_cases
    }

    /// Find a test case by name
    pub fn find_by_name(&self, name: &str) -> Option<&MerkleTestCase> {
        self.test_cases.iter().find(|tc| tc.name == name)
    }

    /// Get test cases with a specific number of leaves
    pub fn filter_by_leaf_count(&self, count: usize) -> Vec<&MerkleTestCase> {
        self.test_cases.iter().filter(|tc| tc.leaves.len() == count).collect()
    }

    /// Get test cases within a range of leaf counts
    pub fn filter_by_leaf_range(&self, min: usize, max: usize) -> Vec<&MerkleTestCase> {
        self.test_cases
            .iter()
            .filter(|tc| tc.leaves.len() >= min && tc.leaves.len() <= max)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_fixtures() {
        let fixtures = MerkleTestFixtures::load_default().expect("Failed to load fixtures");

        // Verify we have test cases
        assert!(!fixtures.test_cases.is_empty());

        // Check a specific test case
        let two_leaves =
            fixtures.find_by_name("two_leaves").expect("two_leaves test case not found");
        assert_eq!(two_leaves.leaves.len(), 2);
        assert_eq!(two_leaves.proofs.len(), 2);

        // Verify each proof corresponds to the right leaf
        for proof in &two_leaves.proofs {
            assert_eq!(proof.leaf, two_leaves.leaves[proof.index]);
        }
    }

    #[test]
    fn test_filter_fixtures() {
        let fixtures = MerkleTestFixtures::load_default().expect("Failed to load fixtures");

        // Filter by exact count
        let four_leaf_cases = fixtures.filter_by_leaf_count(4);
        assert!(!four_leaf_cases.is_empty());
        for case in four_leaf_cases {
            assert_eq!(case.leaves.len(), 4);
        }

        // Filter by range
        let small_cases = fixtures.filter_by_leaf_range(2, 8);
        assert!(!small_cases.is_empty());
        for case in small_cases {
            assert!(case.leaves.len() >= 2 && case.leaves.len() <= 8);
        }
    }
}
