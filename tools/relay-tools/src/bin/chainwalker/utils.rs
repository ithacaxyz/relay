use alloy::primitives::{ChainId, U256, utils::format_units};
use std::collections::HashSet;

/// Format a chain ID with its name if known
pub fn format_chain(chain_id: ChainId) -> String {
    let chain = alloy_chains::Chain::from(chain_id);
    let Some(named) = chain.named() else {
        return format!("{{{chain_id}}}");
    };
    format!("{{ {named}|{chain_id} }}")
}

/// Format units with proper error handling, returning the raw value as string on error
pub fn format_units_safe(value: U256, decimals: u8) -> String {
    format_units(value, decimals).unwrap_or_else(|_| value.to_string())
}

/// Normalize an amount from one decimal precision to another
pub fn normalize_amount(amount: U256, from_decimals: u8, to_decimals: u8) -> U256 {
    if from_decimals == to_decimals {
        amount
    } else if from_decimals > to_decimals {
        // Source has more decimals, divide to reduce precision
        amount / U256::from(10).pow(U256::from(from_decimals - to_decimals))
    } else {
        // Source has fewer decimals, multiply to increase precision
        amount * U256::from(10).pow(U256::from(to_decimals - from_decimals))
    }
}

/// Find an Eulerian path in a complete directed graph.
/// Returns a sequence of edges (from_idx, to_idx) that visits every edge exactly once.
///
/// # Arguments
/// * `n` - Number of nodes in the graph
/// * `start` - Starting node index (0-based)
///
/// # Returns
/// A vector of (from, to) pairs representing edges in the path
pub fn find_eulerian_path_indices(n: usize, start: usize) -> Vec<(usize, usize)> {
    if n < 2 {
        return vec![];
    }

    let mut path = Vec::new();
    let mut visited_edges = HashSet::new();
    let mut current = start;
    let total_edges = n * (n - 1);

    // Visit all edges using the systematic approach
    while visited_edges.len() < total_edges {
        let mut moved = false;

        // Try each possible offset in order (1, 2, ..., n-1)
        for offset in 1..n {
            let next = (current + offset) % n;
            let edge = (current, next);

            if !visited_edges.contains(&edge) {
                path.push(edge);
                visited_edges.insert(edge);
                current = next;
                moved = true;
                break;
            }
        }

        if !moved {
            // This shouldn't happen in a complete directed graph
            panic!("Failed to find next edge from node {current} (n={n})");
        }
    }

    path
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_eulerian_path_various_sizes() {
        for n in 2..=10 {
            let path = find_eulerian_path_indices(n, 0);
            let expected_edges = n * (n - 1);

            assert_eq!(
                path.len(),
                expected_edges,
                "For {} chains, expected {} edges but got {}",
                n,
                expected_edges,
                path.len()
            );

            // Verify no duplicate edges
            let edges: HashSet<(usize, usize)> = path.iter().cloned().collect();
            assert_eq!(edges.len(), expected_edges, "Found duplicate edges for {n} chains");

            // Verify all possible edges are included
            for i in 0..n {
                for j in 0..n {
                    if i != j {
                        assert!(edges.contains(&(i, j)), "Missing edge {i} -> {j} for {n} chains");
                    }
                }
            }

            // Verify it forms a continuous path
            for idx in 0..path.len() - 1 {
                assert_eq!(
                    path[idx].1,
                    path[idx + 1].0,
                    "Path broken at index {idx} for {n} chains"
                );
            }
        }
    }

    #[test]
    fn test_eulerian_path_different_starts() {
        // Test that we can start from any node
        for n in 3..=6 {
            for start in 0..n {
                let path = find_eulerian_path_indices(n, start);
                assert_eq!(path[0].0, start, "Path should start at node {start} for {n} chains");
                assert_eq!(path.len(), n * (n - 1));
            }
        }
    }
}
