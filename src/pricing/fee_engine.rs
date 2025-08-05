//! Comprehensive fee calculation engine for transaction pricing.
//!
//! This module consolidates all fee-related functionality including:
//! - EIP-1559 fee estimation
//! - Gas calculation and intrinsic costs
//! - L1 data availability fees for rollups
//! - Price conversions between ETH and fee tokens

use crate::{
    chains::Chain,
    config::QuoteConfig,
    error::PricingError,
    price::PriceOracle,
    provider::ProviderExt,
    types::{GasEstimate, Intent, Token},
};
use alloy::{
    consensus::{SignableTransaction, TxEip1559},
    eips::eip7702::constants::PER_EMPTY_ACCOUNT_COST,
    primitives::{Address, U256},
    providers::{Provider, utils::Eip1559Estimation},
    rpc::types::FeeHistory,
    signers::Signature,
};
use tracing::instrument;

/// Comprehensive fee calculation engine for transaction pricing.
///
/// This engine handles all aspects of fee calculation including EIP-1559 gas pricing,
/// intrinsic gas costs, L1 data availability fees, and price conversions between
/// native ETH and ERC20 fee tokens.
#[derive(Debug)]
pub struct FeeEngine<'a> {
    price_oracle: &'a PriceOracle,
    quote_config: &'a QuoteConfig,
}

impl<'a> FeeEngine<'a> {
    /// Creates a new fee engine with the given price oracle and quote configuration.
    pub fn new(price_oracle: &'a PriceOracle, quote_config: &'a QuoteConfig) -> Self {
        Self { price_oracle, quote_config }
    }

    // =================================
    // EIP-1559 Fee Estimation
    // =================================

    /// Fetches fee history and analyzes it to produce fee estimates.
    #[instrument(skip_all)]
    pub async fn fetch_and_analyze<P: Provider>(
        provider: &P,
        priority_fee_percentile: f64,
    ) -> Result<Eip1559Estimation, PricingError> {
        use alloy::providers::utils::EIP1559_FEE_ESTIMATION_PAST_BLOCKS;

        let fee_history = provider
            .get_fee_history(
                EIP1559_FEE_ESTIMATION_PAST_BLOCKS,
                Default::default(),
                &[priority_fee_percentile],
            )
            .await
            .map_err(|e| PricingError::FeeHistoryUnavailable(e.to_string()))?;

        Self::estimate_fees(&fee_history)
    }

    /// Estimates fees from fee history data.
    pub fn estimate_fees(fee_history: &FeeHistory) -> Result<Eip1559Estimation, PricingError> {
        use alloy::providers::utils::Eip1559Estimator;

        let estimator = Eip1559Estimator::default();
        let base_fee = fee_history.latest_block_base_fee().unwrap_or_default();
        let rewards = fee_history.reward.as_deref().unwrap_or(&[]);

        Ok(estimator.estimate(base_fee, rewards))
    }

    /// Calculates payment per gas in fee token units.
    ///
    /// Converts native gas price (in wei) to fee token units using the current exchange rate.
    #[instrument(skip_all)]
    pub async fn calculate_payment_per_gas(
        &self,
        fee_estimate: &Eip1559Estimation,
        token: &Token,
    ) -> Result<f64, PricingError> {
        // Get ETH price in token units
        let eth_price = self
            .price_oracle
            .eth_price(token.kind)
            .await
            .ok_or(PricingError::UnavailablePrice(token.address))?;

        // Convert from wei to token units
        // Formula: (gas_price_wei * 10^token_decimals) / eth_price_in_token
        let eth_price_f64 = f64::from(eth_price);

        // Prevent division by zero
        if eth_price_f64 == 0.0 {
            return Err(PricingError::PriceOracleUnavailable("ETH price is zero".to_string()));
        }

        let payment_per_gas = (fee_estimate.max_fee_per_gas as f64
            * 10u128.pow(token.decimals as u32) as f64)
            / eth_price_f64;

        Ok(payment_per_gas)
    }

    /// Extracts the priority fee from an EIP-1559 estimate.
    pub fn get_priority_fee(estimate: &Eip1559Estimation) -> U256 {
        U256::from(estimate.max_priority_fee_per_gas)
    }

    /// Extracts the max fee per gas from an EIP-1559 estimate.
    pub fn get_max_fee(estimate: &Eip1559Estimation) -> U256 {
        U256::from(estimate.max_fee_per_gas)
    }

    // =================================
    // Gas Estimation and Intrinsic Costs
    // =================================

    /// Estimates combined gas for intent and transaction.
    ///
    /// The recommended transaction gas is calculated according to the contracts recommendation:
    /// https://github.com/ithacaxyz/account/blob/feffa280d5de487223e43a69126f5b6b3d99a10a/test/SimulateExecute.t.sol#L205-L206
    pub fn estimate_combined_gas(&self, simulation_gas: U256, intrinsic_gas: u64) -> GasEstimate {
        GasEstimate::from_combined_gas(simulation_gas.to::<u64>(), intrinsic_gas, self.quote_config)
    }

    /// Calculates the intrinsic cost of a transaction.
    ///
    /// This function assumes Prague rules and includes:
    /// - Base transaction cost (21000 gas)
    /// - Data cost (4 gas per zero byte, 16 gas per non-zero byte per Istanbul rules)
    /// - Optional EIP-7702 authorization cost
    pub fn calculate_intrinsic_cost(call_data: &[u8], has_authorization: bool) -> u64 {
        let zero_data_len = call_data.iter().filter(|v| **v == 0).count() as u64;
        let non_zero_data_len = call_data.len() as u64 - zero_data_len;

        // Gas costs per Istanbul rules
        const NON_ZERO_DATA_COST: u64 = 16;
        const ZERO_DATA_COST: u64 = 4;
        const BASE_TX_COST: u64 = 21000;

        let data_gas = zero_data_len * ZERO_DATA_COST + non_zero_data_len * NON_ZERO_DATA_COST;
        let auth_gas = if has_authorization { PER_EMPTY_ACCOUNT_COST } else { 0 };

        BASE_TX_COST + data_gas + auth_gas
    }

    /// Calculates the intrinsic cost for an encoded call.
    ///
    /// Convenience method that takes encoded call data directly.
    pub fn calculate_intrinsic_for_encoded(encoded_call: &[u8], has_authorization: bool) -> u64 {
        Self::calculate_intrinsic_cost(encoded_call, has_authorization)
    }

    /// Extracts the intent gas limit from a gas estimate.
    pub fn get_intent_gas_limit(estimate: &GasEstimate) -> U256 {
        U256::from(estimate.intent)
    }

    /// Extracts the transaction gas limit from a gas estimate.
    pub fn get_tx_gas_limit(estimate: &GasEstimate) -> U256 {
        U256::from(estimate.tx)
    }

    // =================================
    // L1 Fee Estimation for Rollups
    // =================================

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

    // =================================
    // Price Conversion Utilities
    // =================================

    /// Converts native token amount to fee token amount.
    ///
    /// Used for converting ETH amounts to ERC20 token amounts.
    pub async fn convert_native_to_token(
        &self,
        native_amount: U256,
        token: &Token,
    ) -> Result<U256, PricingError> {
        let eth_price = self
            .price_oracle
            .eth_price(token.kind)
            .await
            .ok_or(PricingError::UnavailablePrice(token.address))?;

        // Convert from native to token units
        let token_amount =
            native_amount * U256::from(10u128.pow(token.decimals as u32)) / eth_price;

        Ok(token_amount)
    }

    /// Converts fee token amount to native token amount.
    ///
    /// Used for converting ERC20 token amounts to ETH amounts.
    pub async fn convert_token_to_native(
        &self,
        token_amount: U256,
        token: &Token,
    ) -> Result<U256, PricingError> {
        let eth_price = self
            .price_oracle
            .eth_price(token.kind)
            .await
            .ok_or(PricingError::UnavailablePrice(token.address))?;

        // Convert from token to native units
        let native_amount =
            token_amount * eth_price / U256::from(10u128.pow(token.decimals as u32));

        Ok(native_amount)
    }
}
