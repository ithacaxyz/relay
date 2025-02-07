use std::time::{Duration, SystemTime, UNIX_EPOCH};

use alloy::{
    primitives::{Address, Keccak256, PrimitiveSignature, B256, U256},
    providers::utils::Eip1559Estimation as AlloyEip1559Estimation,
};
use serde::{Deserialize, Serialize};

use super::Signed;

/// A relay-signed [`Quote`].
pub type SignedQuote = Signed<Quote>;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Quote {
    /// The fee token address.
    pub token: Address,
    /// The amount of the fee token to pay for the call.
    pub amount: U256,
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
        let digest = self.digest();
        SignedQuote::new_unchecked(self, signature, digest)
    }

    pub fn digest(&self) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update(self.amount.to_be_bytes::<32>());
        hasher.update(self.gas_estimate.to_be_bytes());
        hasher.update(self.digest);
        hasher.update(
            self.ttl
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs()
                .to_be_bytes(),
        );
        hasher.finalize()
    }
}

// todo: this is temporary and should be replaced once https://github.com/alloy-rs/alloy/pull/2012 is released
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Eip1559Estimation {
    /// The base fee per gas.
    #[serde(with = "alloy::serde::quantity")]
    pub max_fee_per_gas: u128,
    /// The max priority fee per gas.
    #[serde(with = "alloy::serde::quantity")]
    pub max_priority_fee_per_gas: u128,
}

impl From<AlloyEip1559Estimation> for Eip1559Estimation {
    fn from(
        AlloyEip1559Estimation { max_fee_per_gas, max_priority_fee_per_gas}: AlloyEip1559Estimation,
    ) -> Self {
        Self { max_fee_per_gas, max_priority_fee_per_gas }
    }
}
