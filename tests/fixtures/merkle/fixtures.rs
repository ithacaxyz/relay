//! Integration tests for LazyMerkleTree using Murky fixtures

use super::MerkleTestFixtures;
use relay::types::LazyMerkleTree;

#[test]
fn test_lazy_compact_merkle_tree_with_murky_fixtures() {
    let fixtures = MerkleTestFixtures::load_default().expect("Failed to load Murky fixtures");

    let mut total_tests = 0;
    let mut failures = Vec::new();

    // Test all fixtures in one loop
    for test_case in fixtures.test_cases() {
        total_tests += 1;

        // Create tree from leaves
        let mut tree =
            LazyMerkleTree::from_leaves(test_case.leaves.clone(), test_case.leaves.len()).unwrap();

        // Test root calculation
        match tree.root() {
            Ok(root) => {
                if root != test_case.root {
                    failures.push(format!(
                        "Root mismatch for '{}': expected {:?}, got {:?}",
                        test_case.name, test_case.root, root
                    ));
                }
            }
            Err(_) => {
                if !test_case.leaves.is_empty() {
                    failures.push(format!(
                        "Failed to get root for non-empty tree '{}'",
                        test_case.name
                    ));
                }
            }
        }

        // Test all proofs for this case
        for proof_data in &test_case.proofs {
            match tree.proof(proof_data.index) {
                Ok(proof) => {
                    // Check proof matches expected
                    if proof != proof_data.proof {
                        failures.push(format!(
                            "Proof mismatch for '{}' at index {}: expected {:?}, got {:?}",
                            test_case.name, proof_data.index, proof_data.proof, proof
                        ));
                    }

                    // Verify proof is valid
                    if !LazyMerkleTree::verify_proof(&test_case.root, &proof, &proof_data.leaf) {
                        failures.push(format!(
                            "Proof verification failed for '{}' at index {}",
                            test_case.name, proof_data.index
                        ));
                    }
                }
                Err(e) => {
                    // Handle expected errors
                    if test_case.leaves.len() == 1 {
                        // Single leaf tree should not have proofs
                        continue;
                    }
                    failures.push(format!(
                        "Failed to generate proof for '{}' at index {}: {:?}",
                        test_case.name, proof_data.index, e
                    ));
                }
            }
        }

        // Additional validation for edge cases
        match test_case.name.as_str() {
            "single_leaf" => {
                // Single leaf should return itself as root
                if test_case.leaves.len() == 1
                    && let Ok(root) = tree.root()
                    && root != test_case.leaves[0]
                {
                    failures
                        .push(format!("Single leaf tree should return leaf as root, got {root:?}"));
                }
            }
            "empty_tree" => {
                // Empty tree should return None for root
                if test_case.leaves.is_empty() && tree.root().is_ok() {
                    failures.push("Empty tree should return None for root".to_string());
                }
            }
            _ => {}
        }
    }

    // Print report if there are any failures
    if !failures.is_empty() {
        println!("\n=== LazyMerkleTree Test Report ===");
        println!("Total test cases: {total_tests}");
        println!("Failures: {}", failures.len());
        println!("\nFailure details:");
        for (i, failure) in failures.iter().enumerate() {
            println!("  {}. {}", i + 1, failure);
        }
        panic!("\n{} test failures out of {} total tests", failures.len(), total_tests);
    }
}
