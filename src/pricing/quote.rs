//! Quote generation framework for intent pricing and fee coordination.

use crate::{
    chains::Chain,
    config::QuoteConfig,
    error::PricingError,
    price::PriceOracle,
    pricing::fee_engine::FeeEngine,
    types::{GasEstimate, Intent, Quote, Token},
};
use alloy::{
    primitives::{Address, ChainId, U256},
    providers::{Provider, utils::Eip1559Estimation},
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

/// Quote generator that orchestrates fee calculation and quote creation.
///
/// This component coordinates the entire quote generation process by:
/// - Using FeeEngine for low-level fee calculations
/// - Orchestrating gas estimation, pricing, and L1 fees
/// - Generating complete Quote objects with all required fields
#[derive(Debug)]
pub struct QuoteGenerator<'a> {
    /// Price oracle for token conversions.
    price_oracle: &'a PriceOracle,
    /// Quote configuration.
    quote_config: &'a QuoteConfig,
}

impl<'a> QuoteGenerator<'a> {
    /// Creates a new quote generator with the given dependencies.
    pub fn new(price_oracle: &'a PriceOracle, quote_config: &'a QuoteConfig) -> Self {
        Self { price_oracle, quote_config }
    }

    /// Generates a complete quote with calculated fees for an intent.
    ///
    /// This orchestrates the entire quote generation process:
    /// 1. Fetches and analyzes fee history for gas pricing
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
    ) -> Result<Quote, PricingError> {
        // Create fee engine for all calculations
        let fee_engine = FeeEngine::new(self.price_oracle, self.quote_config);

        // Step 1: Fetch and analyze fee history
        let fee_estimate =
            FeeEngine::fetch_and_analyze(provider, context.priority_fee_percentile).await?;

        // Step 2: Calculate gas estimates
        let gas_estimate = fee_engine.estimate_combined_gas(simulation_gas, intrinsic_gas);

        // Step 3: Calculate payment per gas in fee token units
        let payment_per_gas =
            fee_engine.calculate_payment_per_gas(&fee_estimate, &context.fee_token).await?;

        // Get ETH price for the quote
        let eth_price = self
            .price_oracle
            .eth_price(context.fee_token.kind)
            .await
            .ok_or(PricingError::UnavailablePrice(context.fee_token.address))?;

        // Step 4: Calculate extra fees (L1 data availability, etc.)
        let extra_payment_native = FeeEngine::estimate_l1_fee(provider, chain, &intent).await?;

        // Convert extra payment to fee token units
        let extra_payment = if extra_payment_native.is_zero() {
            U256::ZERO
        } else {
            fee_engine.convert_native_to_token(extra_payment_native, &context.fee_token).await?
        };

        // Step 4: Generate quote
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
    ) -> Result<Quote, PricingError> {
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
