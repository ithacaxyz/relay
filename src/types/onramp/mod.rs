//! Onramp types.

use alloy::primitives::Address;
use serde::{Deserialize, Serialize};

pub mod banxa;

/// A normalized quote from an onramp provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnrampQuote {
    /// The fiat amount in the specified fiat currency.
    pub fiat_amount: f32,
    /// The fiat currency.
    pub fiat_currency: OnrampFiatCurrency,
    /// The crypto amount in the specified crypto currency.
    pub crypto_amount: f32,
    /// The crypto currency.
    pub crypto_currency: OnrampCryptoCurrency,
    /// The exchange rate between the fiat and crypto currencies.
    pub exchange_rate: f32,
    /// The fees associated with the onramp transaction.
    pub fees: f32,
}

/// An enum representing the fiat currencies supported by onramp providers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnrampFiatCurrency {
    /// USD.
    Usd,
}

/// An enum representing the crypto currencies supported by onramp providers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnrampCryptoCurrency {
    /// USDC.
    Usdc,
}

/// An enum representing countries/regions supported by onramp providers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OnrampCountry {
    /// US.
    US,
    /// EU.
    EU,
    /// Canada.
    CA,
}

/// Payment methods supported by onramp providers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PaymentMethod {
    /// Apple Pay.
    ApplePay,
}

/// Parameters for `onramp_getQuote`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OnrampQuoteParameters {
    /// The target crypto currency.
    pub crypto_currency: OnrampCryptoCurrency,
    /// The desired payment currency.
    pub fiat_currency: OnrampFiatCurrency,
    /// The target amount (not in base units).
    pub target_amount: f32,
    /// The address to send the funds to.
    pub address: Address,
    /// The country/region of the user.
    pub country: OnrampCountry,
    /// The desired payment method.
    pub payment_method: PaymentMethod,
}
