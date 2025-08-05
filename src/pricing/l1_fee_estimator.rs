//! L1 fee estimation for rollup chains.

use crate::{chains::Chain, error::PricingError, provider::ProviderExt, types::Intent};
use alloy::{
    consensus::{SignableTransaction, TxEip1559},
    primitives::{Address, U256},
    providers::Provider,
    signers::Signature,
};
use tracing::instrument;

/// L1 fee estimator for calculating data availability fees on rollup chains.
#[derive(Debug)]
pub struct L1FeeEstimator;

impl L1FeeEstimator {
    /// Calculates L1 data availability fees for rollup chains.
    ///
    /// This includes L1 data availability fees for Optimism rollups and other L2s.
    #[instrument(skip_all)]
    pub async fn estimate_l1_fee<P: Provider>(
        provider: &P,
        chain: &Chain,
        intent: &Intent,
    ) -> Result<U256, PricingError> {
        // Include the L1 DA fees if we're on an OP rollup
        let fee = if chain.is_optimism {
            // Create a dummy transaction with all fields set to max values
            // to ensure calldata is largest possible
            let tx = TxEip1559 {
                chain_id: chain.chain_id,
                nonce: u64::MAX,
                gas_limit: u64::MAX,
                max_fee_per_gas: u128::MAX,
                max_priority_fee_per_gas: u128::MAX,
                to: (!Address::ZERO).into(),
                input: intent.encode_execute(),
                ..Default::default()
            };
            let signature = Signature::new(U256::MAX, U256::MAX, true);

            let encoded = {
                let tx = tx.into_signed(signature);
                let mut buf = Vec::with_capacity(tx.eip2718_encoded_length());
                tx.eip2718_encode(&mut buf);
                buf
            };

            provider
                .estimate_l1_fee(encoded.into())
                .await
                .map_err(|e| PricingError::PriceCalculationFailed(e.to_string()))?
        } else {
            U256::ZERO
        };

        Ok(fee)
    }
}