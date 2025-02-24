//! Quote types.

use crate::types::Signed;
use alloy::{
    primitives::{Address, B256, Keccak256, PrimitiveSignature, U256},
    providers::utils::Eip1559Estimation,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::GasEstimate;

/// A relay-signed [`Quote`].
pub type SignedQuote = Signed<Quote>;

/// A quote from a relay for a given [`UserOp`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Quote {
    /// The fee token address.
    pub token: Address,
    /// The amount of the fee token to pay for the call.
    pub amount: U256,
    /// The estimated amount of gas the action will consume.
    pub gas_estimate: GasEstimate,
    /// The fee estimate for the action in the destination chains native token.
    pub native_fee_estimate: Eip1559Estimation,
    /// The digest of the [`UserOp`][crate::types::UserOp].
    pub digest: B256,
    /// The time at which this estimate expires.
    ///
    /// This is a UNIX timestamp in seconds.
    #[serde(with = "crate::serde::timestamp")]
    pub ttl: SystemTime,
    /// An optional unsigned authorization item.
    ///
    /// The account in `op.eoa` will be delegated to this address.
    pub authorization_address: Option<Address>,
}

impl Quote {
    /// Add a signature turning the quote into a [`SignedQuote`].
    pub fn into_signed(self, signature: PrimitiveSignature) -> SignedQuote {
        let digest = self.digest();
        SignedQuote::new_unchecked(self, signature, digest)
    }

    /// Compute a digest of the quote for signing.
    pub fn digest(&self) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update(self.amount.to_be_bytes::<32>());
        hasher.update(self.gas_estimate.op.to_be_bytes());
        hasher.update(self.gas_estimate.tx.to_be_bytes());
        hasher.update(self.digest);
        hasher.update(
            self.ttl
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs()
                .to_be_bytes(),
        );
        if let Some(address) = self.authorization_address {
            hasher.update(address);
        }
        hasher.finalize()
    }
}
