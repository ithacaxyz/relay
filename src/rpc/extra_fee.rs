//! Extra fee info for L2s
use alloy::primitives::U256;

/// Contains information about the extra fee on L2 transactions, these come from costs that the L2
/// incurs when posting the transaction on the parent chain.
#[derive(Debug)]
pub enum ExtraFeeInfo {
    /// Arbitrum L2 with L1 DA fee components.
    ///
    /// On arbitrum chains, the extra fee is also required to be added to the gas limit for the
    /// transaction:
    /// https://docs.arbitrum.io/build-decentralized-apps/how-to-estimate-gas#breaking-down-the-formula
    Arbitrum {
        /// L1 gas estimate for the transaction
        l1_gas_estimate: u64,
        /// L1 base fee estimate
        l1_base_fee_estimate: U256,
    },
    /// Optimism L2 with calculated L1 fee.
    ///
    /// On optimism chains, the extra fee is deducted from the account directly and does not need
    /// to be included in the gas limit for the transaction:
    /// https://docs.optimism.io/stack/transactions/fees#mechanism
    Optimism {
        /// The L1 fee estimate
        l1_fee: U256,
    },
    /// Not an L2 or no extra fee
    None,
}

impl ExtraFeeInfo {
    /// Returns the calculated extra fee based on the L2 type
    pub fn extra_fee(&self) -> U256 {
        match self {
            Self::Arbitrum { l1_gas_estimate, l1_base_fee_estimate } => {
                *l1_base_fee_estimate * U256::from(*l1_gas_estimate)
            }
            Self::Optimism { l1_fee } => *l1_fee,
            Self::None => U256::ZERO,
        }
    }

    /// Returns the amount of gas to add to the gas limit to account for the l1 fee. This will
    /// return zero on chains that are not arbitrum.
    pub fn extra_l1_gas(&self) -> u64 {
        match self {
            Self::Arbitrum { l1_gas_estimate, .. } => *l1_gas_estimate,
            _ => 0,
        }
    }
}
