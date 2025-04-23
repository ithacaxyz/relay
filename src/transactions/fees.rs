use alloy::{
    consensus::{Transaction, TxEnvelope, TypedTransaction},
    eips::eip1559::Eip1559Estimation,
};
use tracing::instrument;

/// Minimum gas price bump that we assume to be accepted by the network.
///
/// Ref <https://github.com/ethereum-optimism/op-geth/blob/e666543dc5500428ee7c940e54263fe4968c5efd/core/txpool/legacypool/legacypool.go#L168>
/// Ref <https://github.com/paradigmxyz/reth/blob/b312799e081259a2fbdfa91fb6b43f384625bbe2/crates/transaction-pool/src/config.rs#L23-L24>
pub const MIN_GAS_PRICE_BUMP: u128 = 10;

/// Percent by which we bump the base fee when sending a transaction.
///
/// E.g if latest base fee is 100 gwei, the transaction we send will have a base fee of 120 gwei
/// which might potentially be bumped.
const BASE_FEE_DELTA: u128 = 20;

/// By how much can recommended priority fee differ from the one we've set.
///
/// E.g if our transaction has a priority fee of 100 gwei, we will only bump it once recommended
/// priority fee reaches 110 gwei.
const PRIORITY_FEE_THRESHOLD: u128 = 10;

/// Errors which may occur while estimating fees for a replacement transaction.
#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum FeesError {
    /// Failed to bump the fees.
    #[error("can't afford transaction replacement")]
    CantAffordReplacement,
    /// Failed to bump the fees.
    #[error("can't afford latest base fee")]
    CantAffordBaseFee,
}

/// Context for fee estimation.
#[derive(Debug, Clone)]
pub struct FeeContext {
    /// Last block base fee.
    pub last_base_fee: u128,
    /// Recommended priority fee for the transaction.
    pub recommended_priority_fee: u128,
}

impl FeeContext {
    /// Returns the fee estimation for a new transaction.
    pub fn fees_for_new_transaction(
        &self,
        max_tx_fee: u128,
    ) -> Result<Eip1559Estimation, FeesError> {
        if max_tx_fee < self.last_base_fee {
            return Err(FeesError::CantAffordBaseFee);
        }

        let max_fee_per_gas = max_tx_fee.min(self.last_base_fee * (100 + BASE_FEE_DELTA) / 100);

        Ok(Eip1559Estimation {
            max_fee_per_gas,
            max_priority_fee_per_gas: self.recommended_priority_fee.min(max_fee_per_gas),
        })
    }

    /// Returns whether base fee of a transaction should be bumped.
    fn should_bump_base_fee(&self, tx: &TxEnvelope) -> bool {
        tx.max_fee_per_gas() < self.last_base_fee
    }

    /// Returns whether priority fee of a transaction should be bumped.
    fn should_bump_priority_fee(&self, tx: &TxEnvelope) -> bool {
        self.recommended_priority_fee
            > tx.max_priority_fee_per_gas().unwrap_or_default() * (100 + PRIORITY_FEE_THRESHOLD)
                / 100
    }

    /// Returns whether we should bump the fees for a given transaction.
    pub fn should_bump(&self, tx: &TxEnvelope) -> bool {
        self.should_bump_base_fee(tx) || self.should_bump_priority_fee(tx)
    }

    /// Returns whether we can bump the fees for a given transaction.
    #[instrument(skip_all)]
    pub fn prepare_replacement(
        &self,
        tx: &TxEnvelope,
        max_gas_price: u128,
    ) -> Result<Option<TypedTransaction>, FeesError> {
        if !self.should_bump(tx) {
            return Ok(None);
        }

        let max_fee_per_gas = tx.max_fee_per_gas();
        let max_priority_fee_per_gas = tx.max_priority_fee_per_gas().unwrap_or(max_fee_per_gas);

        // Check if we can't afford to send a replacement.
        if max_fee_per_gas * (100 + MIN_GAS_PRICE_BUMP) / 100 > max_gas_price {
            if self.should_bump_base_fee(tx) {
                // If we need to bump the base fee, this is fatal because we don't want to wait for
                // base fee to decrease.
                return Err(FeesError::CantAffordReplacement);
            } else {
                // If we only need to bump the priority fee, it might be fine to wait a bit.
                return Ok(None);
            }
        }

        // Fail if we can't afford the latest base fee.
        if max_gas_price < self.last_base_fee {
            return Err(FeesError::CantAffordBaseFee);
        }

        // Calculate the minimum values for fees that we must set to a replacement tx.
        let min_new_max_fee = max_fee_per_gas * (100 + MIN_GAS_PRICE_BUMP) / 100;
        let min_new_priority_fee = max_priority_fee_per_gas * (100 + MIN_GAS_PRICE_BUMP) / 100;

        let mut best_new_max_fee = max_fee_per_gas;
        let mut best_new_priority_fee = max_priority_fee_per_gas;

        if self.should_bump_base_fee(tx) {
            best_new_max_fee = self.last_base_fee * (100 + BASE_FEE_DELTA) / 100
        }

        if self.should_bump_priority_fee(tx) {
            let priority_fee_increase = self.recommended_priority_fee - max_priority_fee_per_gas;

            // Bump both fees if we need to increase priority fee.
            best_new_max_fee += priority_fee_increase;
            best_new_priority_fee += priority_fee_increase;
        }

        let new_max_fee = best_new_max_fee.max(min_new_max_fee).min(max_gas_price);
        let new_priority_fee = best_new_priority_fee.max(min_new_priority_fee).min(new_max_fee);

        let mut new_tx = TypedTransaction::from(tx.clone());

        match &mut new_tx {
            TypedTransaction::Legacy(tx) => {
                tx.gas_price = new_max_fee;
            }
            TypedTransaction::Eip2930(tx) => {
                tx.gas_price = new_max_fee;
            }
            TypedTransaction::Eip1559(tx) => {
                tx.max_fee_per_gas = new_max_fee;
                tx.max_priority_fee_per_gas = new_priority_fee;
            }
            TypedTransaction::Eip7702(tx) => {
                tx.max_fee_per_gas = new_max_fee;
                tx.max_priority_fee_per_gas = new_priority_fee;
            }
            _ => {}
        }

        Ok(Some(new_tx))
    }
}
