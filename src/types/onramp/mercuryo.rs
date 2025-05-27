//! Mercuryo onramp.

use alloy::primitives::map::HashMap;
use serde::{Deserialize, Serialize};

// Documentation:
// - https://oor-api.redoc.ly
// - https://oor-iframe.redoc.ly

/// Mercuryo Silent Sign-up
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SilentSignUp {
    /// ??
    pub accept: bool,
    /// User email
    pub email: String,
    /// ISO 639-1 standard language codes, defaults to en-US
    pub language_code: String,
    /// SumSub share token
    pub sumsub: String,
}

/// Mercuryo Silent Login
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SilentLogin {
    /// User email
    pub email: String,
    /// User phone number
    pub phone: String,
    /// User UUID (field is required unless email or phone is provided)
    pub user_uuid4: String,
}

/// Payment flow
/// Available: buy, top_up, top_up_spend, spend, partial_top_up_spend, spend_fast_track_terminal
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PaymentFlow {
    /// Buy.
    Buy,
    /// Top up.
    TopUp,
    /// Top up spend.
    TopUpSpend,
    /// Spend.
    Spend,
    /// Partial top up spend.
    PartialTopUpSpend,
    /// Spend fast track terminal.
    SpendFastTrackTerminal,
}

/// A currency.
pub type Currency = String;
/// An amount.
pub type Amount = String;
/// Amount object.
pub type Amounts = HashMap<Currency, Amount>;

/// A Mercuryo buy quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuyQuote {
    /// The amount of crypto to buy.
    pub amount: String,
    /// The buy token.
    pub buy_token: String,
    /// uk, us, zh
    pub consent_required: String,
    /// The currency.
    pub currency: String,
    /// The fee.
    pub fee: Amounts,
    /// The fiat amount.
    pub fiat_amount: Amount,
    /// The fiat currency.
    pub fiat_currency: String,
    /// The KYC limit exceeded.
    pub kyc_limit_exceeded: bool,
    /// The KYC limits.
    pub kyc_limits: bool,
    /// The rate.
    pub rate: String,
    /// The reverse rate.
    pub reverse_rate: String,
    /// The subtotal.
    pub subtotal: Amounts,
    /// The total.
    pub total: Amounts,
    /// HTTP Status Code.
    pub status: String,
    /// The fee parameters.
    pub fee_parameters: FeeParameters,
}

/// A Mercuryo fee parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeParameters {
    /// The fee percent.
    pub fee_percent: String,
    /// The fee min original.
    pub fee_min_original: String,
    /// The currency original.
    pub currency_original: String,
    /// The consent required.
    pub consent_required: String,
    /// The network fees.
    pub network_fees: Amounts,
    /// The processing fees.
    pub processing_fees: Amounts,
    /// The def parameters.
    pub def_parameters: DefParameters,
    /// The additional currencies rates.
    pub additional_currencies_rates: Amounts,
}

/// A Mercuryo def parameters.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DefParameters {
    /// The is us.
    pub is_us: bool,
}
