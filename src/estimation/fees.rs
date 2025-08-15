//! Fee calculation engine for intent pricing.
//!
//! This module handles:
//! - Gas price estimation
//! - L1 data availability fees
//! - Token price conversions
//! - Payment amount calculation

use alloy::eips::eip7702::constants::PER_EMPTY_ACCOUNT_COST;

/// Approximates the intrinsic gas cost for a transaction.
///
/// This function calculates the base cost of a transaction including:
/// - Base transaction cost (21000 gas)
/// - Calldata cost (16 gas per byte, regardless of value)
/// - Optional EIP-7702 authorization cost
///
///
/// # Returns
/// The estimated intrinsic gas cost in gas units
///
/// # Note
/// This is an overestimate as it doesn't account for gas refunds in EIP-7702,
/// and assumes all calldata bytes cost 16 gas (actual cost is 4 for zero bytes on Ethereum).
pub fn approx_intrinsic_cost(input: &[u8], has_auth: bool) -> u64 {
    // for 7702 designations there is an additional gas charge
    //
    // note: this is not entirely accurate, as there is also a gas refund in 7702, but at this
    // point it is not possible to compute the gas refund, so it is an overestimate, as we also
    // need to charge for the account being presumed empty.
    let auth_cost = if has_auth { PER_EMPTY_ACCOUNT_COST } else { 0 };

    // We just assume gas cost to cost 16 gas per token to eliminate fluctuations in gas estimates
    // due to calldata values changing. A more robust approach here is either only doing an
    // upperbound for calldata ranges that will change and doing a more accurate estimate for
    // calldata ranges we know to be fixed (e.g. the EOA address), or just sending the calldata to
    // an empty address on the chain the intent is for to get an estimate of the calldata.
    21000 + auth_cost + input.len() as u64 * 16
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        providers::utils::{Eip1559Estimation, Eip1559Estimator},
        rpc::types::FeeHistory,
    };

    #[test]
    fn test_approx_intrinsic_cost_without_auth() {
        // Test with empty calldata and no auth
        assert_eq!(approx_intrinsic_cost(&[], false), 21000);

        // Test with some calldata and no auth
        let calldata = vec![0u8; 100];
        assert_eq!(approx_intrinsic_cost(&calldata, false), 21000 + 100 * 16);
    }

    #[test]
    fn test_approx_intrinsic_cost_with_auth() {
        // Test with empty calldata and auth
        assert_eq!(approx_intrinsic_cost(&[], true), 21000 + PER_EMPTY_ACCOUNT_COST);

        // Test with some calldata and auth
        let calldata = vec![0u8; 100];
        assert_eq!(
            approx_intrinsic_cost(&calldata, true),
            21000 + PER_EMPTY_ACCOUNT_COST + 100 * 16
        );
    }

    #[test]
    fn test_approx_intrinsic_cost_large_calldata() {
        // Test with large calldata
        let calldata = vec![0xff; 1000];
        assert_eq!(approx_intrinsic_cost(&calldata, false), 21000 + 1000 * 16);
    }

    // feehistory response public bsc endpoint <https://bsc-dataseed.bnbchain.org>
    #[test]
    fn fee_history_bsc_public_bsc() {
        // for [
        // 		10,
        // 		"latest",
        //       [20.0]
        // 	],
        let sample = r#"{
        "oldestBlock": "0x3706d1a",
        "reward": [
            [
                "0x5f5e100"
            ],
            [
                "0x5f5e100"
            ],
            [
                "0x64"
            ],
            [
                "0x5f5e100"
            ],
            [
                "0x5f5e100"
            ],
            [
                "0x5f5e100"
            ],
            [
                "0x5f5e100"
            ],
            [
                "0x5f5e100"
            ],
            [
                "0x5f5e100"
            ],
            [
                "0x5f5e100"
            ]
        ],
        "baseFeePerGas": [
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0",
            "0x0"
        ],
        "gasUsedRatio": [
            0.28533176,
            0.218322,
            0.15909398666666666,
            0.17449282666666666,
            0.22352961333333332,
            0.26406174666666665,
            0.28206398666666666,
            0.20695654666666666,
            0.22779266666666667,
            0.23267304
        ],
        "baseFeePerBlobGas": [
            "0x1",
            "0x1",
            "0x1",
            "0x1",
            "0x1",
            "0x1",
            "0x1",
            "0x1",
            "0x1",
            "0x1",
            "0x1"
        ],
        "blobGasUsedRatio": [
            0,
            0.16666666666666666,
            0,
            0,
            0,
            0.16666666666666666,
            0,
            0,
            0,
            0.16666666666666666
        ]
    }"#;

        let fee_history = serde_json::from_str::<FeeHistory>(sample).unwrap();

        let last_base_fee = fee_history.latest_block_base_fee().unwrap_or_default();

        let fee_estimate = Eip1559Estimator::default()
            .estimate(last_base_fee, &fee_history.reward.unwrap_or_default());
        // ensure these return 1gwei
        assert_eq!(
            fee_estimate,
            Eip1559Estimation { max_fee_per_gas: 100000000, max_priority_fee_per_gas: 100000000 }
        )
    }

    // feehistory from pro quiknode
    #[test]
    fn fee_history_bsc_quiknode() {
        // for [
        // 		10,
        // 		"latest",
        //       [20.0]
        // 	],
        let sample = r#"{
        "oldestBlock": "0x3706ed7",
        "reward": [
            [
                "0x5f5e100"
            ]
        ],
        "baseFeePerGas": [
            "0x0",
            "0x0"
        ],
        "gasUsedRatio": [
            0.20435928
        ],
        "baseFeePerBlobGas": [
            "0x1",
            "0x1"
        ],
        "blobGasUsedRatio": [
            0.16666666666666666
        ]
    }"#;

        let fee_history = serde_json::from_str::<FeeHistory>(sample).unwrap();

        let last_base_fee = fee_history.latest_block_base_fee().unwrap_or_default();

        let fee_estimate = Eip1559Estimator::default()
            .estimate(last_base_fee, &fee_history.reward.unwrap_or_default());

        // ensure these return 1gwei
        assert_eq!(
            fee_estimate,
            Eip1559Estimation { max_fee_per_gas: 100000000, max_priority_fee_per_gas: 100000000 }
        )
    }
}
