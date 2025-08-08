# Merkle Tree Test Fixtures

This directory contains test fixtures for validating Merkle tree implementations against the Solidity Murky library.

## Files

- `merkle_murky_fixtures.json` - Test fixtures generated from the Murky Solidity implementation
- `mod.rs` - Rust module for loading and using the fixtures

## Fixture Format

The fixtures are stored in JSON format with the following structure:

```json
{
  "test_cases": [
    {
      "name": "test_case_name",
      "root": "0x...",
      "height": 3,
      "leaves": ["0x...", "0x...", ...],
      "proofs": [
        {
          "index": 0,
          "leaf": "0x...",
          "proof": ["0x...", "0x...", ...]
        },
        ...
      ]
    },
    ...
  ]
}
```

## Test Cases

The fixtures include various test cases:

1. **Edge Cases**:
   - `two_leaves` - Minimal tree with 2 leaves
   - `two_identical_leaves` - Tree with duplicate values
   - `two_zero_leaves` - Tree with zero values
   - `mixed_zero_real` - Mix of zero and non-zero values

2. **Sequential and Random Data**:
   - `sequential_N` - Sequential values (3-8 leaves)
   - `random_N` - Random values (3-8 leaves)

3. **Power of 2 Cases**:
   - `power_of_2_4` - 4 leaves
   - `power_of_2_8` - 8 leaves
   - `power_of_2_16` - 16 leaves
   - `power_of_2_32` - 32 leaves

4. **Larger Trees**:
   - `medium_incremental_16` - 16 incremental values
   - `medium_incremental_32` - 32 incremental values
   - `medium_incremental_64` - 64 incremental values
   - `large_addresses_128` - 128 address-like values
   - `large_addresses_256` - 256 address-like values

## Usage

### Loading Fixtures in Tests

```rust
use fixtures::MerkleTestFixtures;

let fixtures = MerkleTestFixtures::load_default()
    .expect("Failed to load fixtures");

// Get a specific test case
let test_case = fixtures.find_by_name("two_leaves")
    .expect("Test case not found");

// Filter test cases
let small_trees = fixtures.filter_by_leaf_count(4);
let medium_trees = fixtures.filter_by_leaf_range(8, 32);
```

### Running Fixture Tests

```bash
# Run all fixture tests
cargo test merkle_fixture_tests

# Run with output to see which cases are being tested
cargo test merkle_fixture_tests -- --nocapture
```

## Validation

These fixtures ensure that the Rust Merkle tree implementations:
- Produce the same roots as the Solidity implementation
- Generate identical proofs for all leaves
- Handle edge cases correctly
- Scale to larger trees appropriately