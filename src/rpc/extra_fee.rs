//! Extra fee info for L2s
use alloy::primitives::U256;

/// Contains information about the extra fee on L2 transactions, these come from costs that the L2
/// incurs when posting the transaction on the parent chain.
#[derive(Debug)]
pub struct ExtraFeeInfo {
    /// The extra fee
    /// TODO: add units to docs
    extra_fee: U256,
    /// Whether or not the fee should be part of the gas limit.
    ///
    /// On optimism chains, the extra fee is deducted from the account directly and does not need
    /// to be included in the gas limit for the transaction:
    /// https://docs.optimism.io/stack/transactions/fees#mechanism
    ///
    /// On arbitrum chains, the extra fee is also required to be added to the gas limit for the
    /// transaction:
    /// https://docs.arbitrum.io/build-decentralized-apps/how-to-estimate-gas#breaking-down-the-formula
    is_paid_in_gas: bool,
}

impl ExtraFeeInfo {
    /// Creates the extra fee info struct. The parameter `is_arbitrum` determines the
    /// `is_paid_in_gas` field, because arbitrum requires extra fee to be paid in gas.
    pub fn new(extra_fee: U256, is_arbitrum: bool) -> Self {
        Self { extra_fee, is_paid_in_gas: is_arbitrum }
    }

    /// Returns the extra fee
    pub fn extra_fee(&self) -> U256 {
        self.extra_fee
    }

    /// Returns the fee to be added to the gas limit
    pub fn additional_gas(&self) -> U256 {
        self.extra_fee
    }
}
