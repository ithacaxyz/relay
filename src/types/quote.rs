use std::time::SystemTime;

use alloy::primitives::{PrimitiveSignature, B256};
use serde::{Deserialize, Serialize};

use super::Signed;

/// A relay-signed [`Quote`].
pub type SignedQuote = Signed<Quote>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Quote {
    /// The amount of the fee token to pay for the call.
    #[serde(with = "alloy::serde::quantity")]
    pub amount: u128,
    /// The estimated amount of gas the action will consume.
    #[serde(with = "alloy::serde::quantity")]
    pub gas_estimate: u64,
    /// The fee estimate for the action in the destination chains native token.
    pub native_fee_estimate: Eip1559Estimation,
    /// The digest of the [`UserOp`][crate::types::UserOp].
    pub digest: B256,
    /// The time at which this estimate expires.
    ///
    /// This is a UNIX timestamp in seconds.
    #[serde(with = "crate::serde::timestamp")]
    pub ttl: SystemTime,
}

impl Quote {
    pub fn into_signed(self, signature: PrimitiveSignature) -> SignedQuote {
        SignedQuote::new_unchecked(self, signature, B256::ZERO)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Eip1559Estimation {
    /// The base fee per gas.
    #[serde(with = "alloy::serde::quantity")]
    pub max_fee_per_gas: u128,
    /// The max priority fee per gas.
    #[serde(with = "alloy::serde::quantity")]
    pub max_priority_fee_per_gas: u128,
}
