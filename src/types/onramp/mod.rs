//! Onramp types.

use alloy::primitives::{Address, B256};
use serde::{Deserialize, Serialize};

pub mod banxa;

/// An order ID.
///
/// This should be treated as an opaque identifier without any specific meaning or serialization.
pub type OrderId = String;

/// The status of an order.
///
/// Order statuses from underlying oramp providers should normalize to this type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OrderStatus {
    /// Waiting for payment confirmation from the customer.
    ///
    /// This can mean a couple of things:
    ///
    /// - The customer has not yet paid at all
    /// - The onramp provider is waiting for payment confirmation from its payment processor
    PaymentPending,
    /// The order is pending extra confirmation, such as KYC.
    VerificationPending,
    /// The order expired, usually because the customer did not pay in time.
    Expired,
    /// The order has been submitted on chain.
    TxSubmitted,
    /// The transaction for the order has been confirmed on chain.
    Completed,
    /// The customer refunded the order through the onramp provider.
    Refunded,
    /// The payment was declined.
    PaymentDeclined,
    /// The order was cancelled by the onramp provider for any number of reasons, incl. internal
    /// risk and compliance alerts, or (in some cases) by the user themselves.
    Cancelled,
}

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
    /// Google Pay.
    GooglePay,
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

/// An onramp order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Order {
    /// The order ID.
    pub order_id: OrderId,
    /// The status of the order.
    pub status: OrderStatus,
    /// The transaction hash of the order if known.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_hash: Option<B256>,
}
