//! Banxa onramp.

use serde::{Deserialize, Serialize};

use super::PaymentMethod;

/// A Banxa buy quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuyQuote {
    /// The payment method.
    pub payment_method: PaymentMethod,
    /// The crypto amount.
    pub crypto_amount: f32,
    /// The price of the crypto in fiat.
    pub fiat_amount: f32,
    /// The processing fee in fiat.
    pub processing_fee: f32,
    /// The network fee in fiat.
    pub network_fee: f32,
}
