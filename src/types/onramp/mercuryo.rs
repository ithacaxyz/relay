//! Mercuryo onramp.

use alloy::primitives::B256;
use serde::{Deserialize, Serialize};

use super::{OnrampCountry, OrderId, PaymentMethod};

/// Documentation:
/// - https://oor-api.redoc.ly
/// - https://oor-iframe.redoc.ly

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
pub enum PaymentFlow {
    Buy,
    TopUp,
    TopUpSpend,
    Spend,
    PartialTopUpSpend,
    SpendFastTrackTerminal,
}

/// A Mercuryo buy quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuyQuote {
    /// Currency to convert from.
    pub from: String,
    /// Currency to convert to.
    pub to: String,
    /// Transaction type
    pub transaction_type: String,
    /// is passed amount with fee (default: true)
    pub is_total: bool,
    /// Chain
    pub network: String,
    /// Payment method (card, volt, apple, google, pix, invoice, spend_card)
    pub payment_method: PaymentMethod,
    /// User wallet address
    pub address: String,
    /// User IP address
    pub ip_address: String,
    /// User country
    pub country: String,
    /// User email
    pub email: String,
    /// Merchant transaction id
    pub merchant_transaction_id: String,
    /// Payment flow
    pub flow: PaymentFlow,
}
