//! Mercuryo onramp.

use alloy::primitives::B256;
use serde::{Deserialize, Serialize};

use super::{OnrampCountry, OrderId, PaymentMethod};

/// A Mercuryo buy quote.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BuyQuote {

}
