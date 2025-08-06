//! Comprehensive fee calculation engine for transaction pricing.
//!
//! This module consolidates all fee-related functionality including:
//! - EIP-1559 fee estimation
//! - Gas calculation and intrinsic costs
//! - L1 data availability fees for rollups
//! - Price conversions between ETH and fee tokens
//! - Quote generation and orchestration

use crate::{
    chains::Chain,
    config::QuoteConfig,
    error::QuoteError,
    price::PriceOracle,
    provider::ProviderExt,
    types::{GasEstimate, Intent, Quote, Token},
};
use alloy::{
    consensus::{SignableTransaction, TxEip1559},
    eips::eip7702::constants::PER_EMPTY_ACCOUNT_COST,
    primitives::{Address, ChainId, U256},
    providers::{Provider, utils::Eip1559Estimation},
    rpc::types::FeeHistory,
    signers::Signature,
};
use tracing::instrument;

/// Context required for pricing calculations.
#[derive(Debug, Clone)]
pub struct PricingContext {
    /// Chain ID for the transaction.
    pub chain_id: ChainId,
    /// Fee token to use for payment.
    pub fee_token: Token,
    /// Whether this is a regular intent or initialization.
    pub is_init: bool,
    /// Current balance of fee token.
    pub fee_token_balance: U256,
    /// Priority fee percentile for gas estimation.
    pub priority_fee_percentile: f64,
}

/// Comprehensive fee calculation engine for transaction pricing.
///
/// This engine handles all aspects of fee calculation including EIP-1559 gas pricing,
/// intrinsic gas costs, L1 data availability fees, and price conversions between
/// native ETH and ERC20 fee tokens.
#[derive(Debug)]
pub struct FeeEngine {
    price_oracle: PriceOracle,
    quote_config: QuoteConfig,
}

impl FeeEngine {
    /// Creates a new fee engine with the given price oracle and quote configuration.
    pub fn new(price_oracle: PriceOracle, quote_config: QuoteConfig) -> Self {
        Self { price_oracle, quote_config }
    }

    /// Fetches fee history and analyzes it to produce fee estimates.
    #[instrument(skip_all)]
    pub async fn fetch_and_analyze<P: Provider>(
        provider: &P,
        priority_fee_percentile: f64,
    ) -> Result<Eip1559Estimation, QuoteError> {
        use alloy::providers::utils::EIP1559_FEE_ESTIMATION_PAST_BLOCKS;

        let fee_history = provider
            .get_fee_history(
                EIP1559_FEE_ESTIMATION_PAST_BLOCKS,
                Default::default(),
                &[priority_fee_percentile],
            )
            .await
            .map_err(|e| QuoteError::FeeHistoryUnavailable(e.to_string()))?;

        Self::estimate_fees(&fee_history)
    }

    /// Estimates fees from fee history data.
    pub fn estimate_fees(fee_history: &FeeHistory) -> Result<Eip1559Estimation, QuoteError> {
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
    ) -> Result<f64, QuoteError> {
        // Get ETH price in token units
        let eth_price = self
            .price_oracle
            .eth_price(token.kind)
            .await
            .ok_or(QuoteError::UnavailablePrice(token.address))?;

        // Convert from wei to token units
        // Formula: (gas_price_wei * 10^token_decimals) / eth_price_in_token
        let eth_price_f64 = f64::from(eth_price);

        // Prevent division by zero
        if eth_price_f64 == 0.0 {
            return Err(QuoteError::PriceCalculationFailed("ETH price is zero".to_string()));
        }

        let payment_per_gas = (fee_estimate.max_fee_per_gas as f64
            * 10u128.pow(token.decimals as u32) as f64)
            / eth_price_f64;

        Ok(payment_per_gas)
    }

    /// Calculates payment per gas in fee token units using pre-fetched ETH price.
    ///
    /// This is an optimized version that avoids redundant price oracle calls.
    fn calculate_payment_per_gas_with_price(
        &self,
        fee_estimate: &Eip1559Estimation,
        token: &Token,
        eth_price: U256,
    ) -> Result<f64, QuoteError> {
        // Convert from wei to token units
        // Formula: (gas_price_wei * 10^token_decimals) / eth_price_in_token
        let eth_price_f64 = f64::from(eth_price);

        // Prevent division by zero
        if eth_price_f64 == 0.0 {
            return Err(QuoteError::PriceCalculationFailed("ETH price is zero".to_string()));
        }

        let payment_per_gas = (fee_estimate.max_fee_per_gas as f64
            * 10u128.pow(token.decimals as u32) as f64)
            / eth_price_f64;

        Ok(payment_per_gas)
    }

    /// Estimates combined gas for intent and transaction.
    ///
    /// The recommended transaction gas is calculated according to the contracts recommendation:
    /// https://github.com/ithacaxyz/account/blob/feffa280d5de487223e43a69126f5b6b3d99a10a/test/SimulateExecute.t.sol#L205-L206
    pub fn estimate_combined_gas(&self, simulation_gas: U256, intrinsic_gas: u64) -> GasEstimate {
        GasEstimate::from_combined_gas(
            simulation_gas.to::<u64>(),
            intrinsic_gas,
            &self.quote_config,
        )
    }

    /// Calculates the intrinsic cost of a transaction.
    ///
    /// This function uses overcharge model and includes:
    /// - Base transaction cost (21000 gas)
    /// - Data cost (16 gas per byte regardless of whether it's zero or non-zero)
    /// - Optional EIP-7702 authorization cost
    pub fn calculate_intrinsic_cost(call_data: &[u8], has_authorization: bool) -> u64 {
        // Gas costs - overcharge model (16 gas per byte regardless of content)
        const DATA_COST_PER_BYTE: u64 = 16;
        const BASE_TX_COST: u64 = 21000;

        let data_gas = call_data.len() as u64 * DATA_COST_PER_BYTE;
        let auth_gas = if has_authorization { PER_EMPTY_ACCOUNT_COST } else { 0 };

        BASE_TX_COST + data_gas + auth_gas
    }

    /// Estimates additional fees to be paid for a intent (e.g L1 DA fees).
    ///
    /// Returns fees in ETH.
    #[instrument(skip_all)]
    pub async fn estimate_extra_fee<P: Provider>(
        provider: &P,
        chain: &Chain,
        intent: &Intent,
    ) -> Result<U256, QuoteError> {
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
                .map_err(|e| QuoteError::GasEstimationFailed(e.to_string()))?
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
    ) -> Result<U256, QuoteError> {
        let eth_price = self
            .price_oracle
            .eth_price(token.kind)
            .await
            .ok_or(QuoteError::UnavailablePrice(token.address))?;

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
    ) -> Result<U256, QuoteError> {
        let eth_price = self
            .price_oracle
            .eth_price(token.kind)
            .await
            .ok_or(QuoteError::UnavailablePrice(token.address))?;

        // Convert from token to native units
        let native_amount =
            token_amount * eth_price / U256::from(10u128.pow(token.decimals as u32));

        Ok(native_amount)
    }

    // =================================
    // Quote Generation and Orchestration
    // =================================

    /// Generates a complete quote with pre-fetched fee history and ETH price.
    ///
    /// This orchestrates the entire quote generation process:
    /// 1. Analyzes pre-fetched fee history for gas pricing
    /// 2. Calculates gas estimates and payment per gas
    /// 3. Computes L1 data availability fees (for rollups)
    /// 4. Converts fees to the specified fee token
    /// 5. Assembles the final Quote object
    #[instrument(skip_all)]
    #[allow(clippy::too_many_arguments)]
    pub async fn calculate_fees<P: Provider + Clone>(
        &self,
        provider: &P,
        chain: &Chain,
        intent: Intent,
        simulation_gas: U256,
        intrinsic_gas: u64,
        context: PricingContext,
        orchestrator: Address,
        authorization_address: Option<Address>,
        fee_history: alloy::rpc::types::FeeHistory,
        eth_price: U256,
    ) -> Result<Quote, QuoteError> {
        // Step 1: Analyze pre-fetched fee history
        let fee_estimate = Self::estimate_fees(&fee_history)?;

        // Step 2: Calculate gas estimates
        let gas_estimate = self.estimate_combined_gas(simulation_gas, intrinsic_gas);

        // Step 3: Calculate payment per gas in fee token units using pre-fetched ETH price
        let payment_per_gas = self.calculate_payment_per_gas_with_price(
            &fee_estimate,
            &context.fee_token,
            eth_price,
        )?;

        // Step 4: Calculate extra fees (L1 data availability, etc.)
        let extra_payment_native = Self::estimate_extra_fee(provider, chain, &intent).await?;

        // Convert extra payment to fee token units
        let extra_payment = if extra_payment_native.is_zero() {
            U256::ZERO
        } else {
            self.convert_native_to_token(extra_payment_native, &context.fee_token).await?
        };

        // Step 5: Generate quote
        let quote = self.generate_quote(
            gas_estimate,
            fee_estimate,
            payment_per_gas,
            extra_payment,
            &context,
            intent,
            eth_price,
            orchestrator,
            authorization_address,
        )?;

        Ok(quote)
    }

    /// Generates a quote from pricing components.
    ///
    /// Note: The caller must set the intent, orchestrator, and authorization_address fields.
    #[allow(clippy::too_many_arguments)]
    fn generate_quote(
        &self,
        gas_estimate: GasEstimate,
        fee_estimate: Eip1559Estimation,
        payment_per_gas: f64,
        extra_payment: U256,
        context: &PricingContext,
        intent: Intent,
        eth_price: U256,
        orchestrator: Address,
        authorization_address: Option<Address>,
    ) -> Result<Quote, QuoteError> {
        // Calculate total payment
        let gas_payment = U256::from((payment_per_gas * gas_estimate.tx as f64).ceil() as u128);
        let total_payment = gas_payment.saturating_add(extra_payment);

        // Ensure minimum payment
        let min_payment = U256::from(1);
        let payment_amount = total_payment.max(min_payment);

        // Update intent with payment amount
        let mut intent_with_payment = intent;
        intent_with_payment.set_legacy_payment_amount(payment_amount);

        // Build the quote
        let quote = Quote {
            chain_id: context.chain_id,
            intent: intent_with_payment,
            extra_payment,
            eth_price,
            payment_token_decimals: context.fee_token.decimals,
            tx_gas: gas_estimate.tx,
            native_fee_estimate: fee_estimate,
            authorization_address,
            orchestrator,
            fee_token_deficit: U256::ZERO, // Will be calculated by caller if needed
        };

        Ok(quote)
    }
}
