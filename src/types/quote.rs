//! Quote types.

use crate::types::{Signed, UserOp};
use alloy::{
    primitives::{Address, B256, ChainId, Keccak256, Signature, U256},
    providers::utils::Eip1559Estimation,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A relay-signed [`Quote`].
pub type SignedQuote = Signed<Quote>;

/// A quote from a relay for a given [`UserOp`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Quote {
    /// Chain id.
    pub chain_id: ChainId,
    /// User op.
    pub op: UserOp,
    /// Extra payment for e.g L1 DA fee that is paid on top of the execution gas.
    pub extra_payment: U256,
    /// Price of the ETH in the [`UserOP::paymentToken`] in wei.
    pub eth_price: U256,
    /// The recommended gas limit for the transaction.
    #[serde(with = "alloy::serde::quantity")]
    pub tx_gas: u64,
    /// The fee estimate for the action in the destination chains native token.
    pub native_fee_estimate: Eip1559Estimation,
    /// The time at which this estimate expires.
    ///
    /// This is a UNIX timestamp in seconds.
    #[serde(with = "crate::serde::timestamp")]
    pub ttl: SystemTime,
    /// An optional unsigned authorization item.
    ///
    /// The account in `op.eoa` will be delegated to this address.
    pub authorization_address: Option<Address>,
    /// Entrypoint to use for the transaction.
    pub entrypoint: Address,
}

impl Quote {
    /// Add a signature turning the quote into a [`SignedQuote`].
    pub fn into_signed(self, signature: Signature) -> SignedQuote {
        let digest = self.digest();
        SignedQuote::new_unchecked(self, signature, digest)
    }

    /// Compute a digest of the quote for signing.
    pub fn digest(&self) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update(self.chain_id.to_be_bytes());
        if let Some(address) = self.authorization_address {
            hasher.update(address);
        }
        hasher.update(self.op.digest());
        hasher.update(
            self.ttl
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs()
                .to_be_bytes(),
        );
        hasher.update(self.entrypoint);
        hasher.finalize()
    }
}
