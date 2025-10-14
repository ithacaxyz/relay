//! Quote types.

use crate::{
    error::RelayError,
    types::{AssetDeficits, Intent, Intents, Signed, VersionedContracts},
};
use alloy::{
    primitives::{Address, B256, ChainId, Keccak256, Sealable, Signature, U256},
    providers::utils::Eip1559Estimation,
    rpc::types::SignedAuthorization,
};
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// A relay-signed [`Quotes`].
pub type SignedQuotes = Signed<Quotes>;

/// A set of quotes from the relay with a set of intents.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Quotes {
    /// A quote for each intent.
    ///
    /// For a single-chain workflow, this will have exactly one item, the output intent.
    ///
    /// For a multi-chain workflow, this will have multiple items, where the last one is the output
    /// intent.
    pub quotes: Vec<Quote>,
    /// The time at which this estimate expires.
    ///
    /// This is a UNIX timestamp in seconds.
    #[serde(with = "crate::serde::timestamp")]
    pub ttl: SystemTime,
    /// Merkle root if it's a multichain
    pub multi_chain_root: Option<B256>,
    /// Optional quote for the fee payer.
    pub fee_payer_quote: Option<Box<Quote>>,
}

impl Quotes {
    /// Sets the merkle payload to every quote.
    pub fn with_merkle_payload(
        mut self,
        contracts: &VersionedContracts,
    ) -> Result<Self, RelayError> {
        let mut intents = Intents::new(
            self.quotes
                .iter()
                .map(|quote| {
                    Ok((
                        quote.intent.clone(),
                        contracts.get_versioned_orchestrator(quote.orchestrator)?.clone(),
                        quote.chain_id,
                    ))
                })
                .collect::<Result<Vec<_>, RelayError>>()?,
        );

        self.multi_chain_root = Some(intents.root()?);

        Ok(self)
    }

    /// Get the total fees in all of the inner quotes combined.
    ///
    /// For now, this assumes a uniform fee token across all intents, but we may change this in the
    /// future.
    ///
    /// Returns `None` if there are no inner quotes.
    pub fn fees(&self) -> Option<(Address, U256)> {
        Some((
            self.quotes.first()?.intent.payment_token(),
            self.quotes.iter().map(|quote| quote.intent.total_payment_max_amount()).sum(),
        ))
    }

    /// Add a signature turning the quotes into a [`SignedQuotes`].
    pub fn into_signed(self, signature: Signature) -> SignedQuotes {
        let digest = self.digest();
        SignedQuotes::new_unchecked(self, signature, digest)
    }

    /// Compute a digest of the quotes for signing.
    pub fn digest(&self) -> B256 {
        let mut hasher = Keccak256::new();
        for quote in &self.quotes {
            hasher.update(quote.digest());
        }
        hasher.update(
            self.ttl
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0))
                .as_secs()
                .to_be_bytes(),
        );
        if let Some(root) = self.multi_chain_root {
            hasher.update(root);
        }
        hasher.finalize()
    }
}

impl Sealable for Quotes {
    fn hash_slow(&self) -> B256 {
        self.digest()
    }
}

/// A quote from a relay for a given [`Intent`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Quote {
    /// The chain ID.
    #[serde(with = "alloy::serde::quantity")]
    pub chain_id: ChainId,
    /// The intent.
    pub intent: Intent,
    /// Extra payment for e.g L1 DA fee that is paid on top of the execution gas.
    pub extra_payment: U256,
    /// Price of the ETH in the [`Intent::paymentToken`] in wei.
    pub eth_price: U256,
    /// Decimals of the [`Intent::paymentToken`].
    pub payment_token_decimals: u8,
    /// The recommended gas limit for the transaction.
    #[serde(with = "alloy::serde::quantity")]
    pub tx_gas: u64,
    /// The fee estimate for the action in the destination chains native token.
    pub native_fee_estimate: Eip1559Estimation,
    /// An optional unsigned authorization item.
    ///
    /// The account in `intent.eoa` will be delegated to this address.
    pub authorization_address: Option<Address>,
    /// An optional additional authorization address, which would be used to delegate the feepayer
    pub additional_authorization: Option<SignedAuthorization>,
    /// Orchestrator to use for the transaction.
    pub orchestrator: Address,
    /// How much of the fee token the fee payer (or user if no fee payer) is missing to pay for
    /// this intent.
    ///
    /// If it is 0, the fee payer has enough balance to execute the call.
    #[serde(default)]
    pub fee_token_deficit: U256,
    /// Assets user is missing for the intent to execute correctly.
    #[serde(default, skip_serializing_if = "AssetDeficits::is_empty")]
    pub asset_deficits: AssetDeficits,
}

impl Quote {
    /// Returns true if the quote has deficits.
    pub fn has_deficits(&self) -> bool {
        !self.asset_deficits.is_empty() || !self.fee_token_deficit.is_zero()
    }

    /// Compute a digest of the quote for signing.
    pub fn digest(&self) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update(self.chain_id.to_be_bytes());
        hasher.update(self.intent.digest());
        hasher.update(self.extra_payment.to_be_bytes::<32>());
        hasher.update(self.eth_price.to_be_bytes::<32>());
        hasher.update([self.payment_token_decimals]);
        hasher.update(self.tx_gas.to_be_bytes());
        hasher.update(self.native_fee_estimate.max_fee_per_gas.to_be_bytes());
        hasher.update(self.native_fee_estimate.max_priority_fee_per_gas.to_be_bytes());
        if let Some(address) = self.authorization_address {
            hasher.update(address);
        }
        if let Some(auth) = &self.additional_authorization {
            hasher.update(auth.signature_hash());
        }
        hasher.update(self.orchestrator);
        hasher.update([self.has_deficits() as u8]);
        hasher.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that ensures all fields in Quote affect the digest.
    ///
    /// This test uses exhaustive struct initialization which will cause a compile error
    /// if a new field is added to Quote but not included in the test, forcing developers
    /// to update both the digest method and this test.
    #[test]
    fn test_quote_digest_includes_all_fields() {
        // Helper macro to test that modifying a field changes the digest
        macro_rules! test_field {
            ($base:expr, $field:ident, $new_value:expr, $msg:expr) => {{
                let mut modified = $base.clone();
                modified.$field = $new_value;
                assert_ne!($base.digest(), modified.digest(), $msg);
            }};
        }

        // Base quote - using exhaustive initialization (no `..Default::default()`)
        // This will fail to compile if a new field is added
        let base_quote = Quote {
            chain_id: 1,
            intent: Intent::default(),
            extra_payment: U256::from(100),
            eth_price: U256::from(2000),
            payment_token_decimals: 18,
            tx_gas: 21000,
            native_fee_estimate: Eip1559Estimation {
                max_fee_per_gas: 100,
                max_priority_fee_per_gas: 10,
            },
            authorization_address: Some(Address::ZERO),
            additional_authorization: None,
            orchestrator: Address::ZERO,
            fee_token_deficit: U256::ZERO,
            asset_deficits: AssetDeficits::default(),
        };

        // Test each field affects digest
        test_field!(base_quote, chain_id, 2, "chain_id must affect digest");
        test_field!(base_quote, extra_payment, U256::from(200), "extra_payment must affect digest");
        test_field!(base_quote, eth_price, U256::from(3000), "eth_price must affect digest");
        test_field!(
            base_quote,
            payment_token_decimals,
            6,
            "payment_token_decimals must affect digest"
        );
        test_field!(base_quote, tx_gas, 50000, "tx_gas must affect digest");

        // Test native_fee_estimate fields
        let mut modified = base_quote.clone();
        modified.native_fee_estimate.max_fee_per_gas = 200;
        assert_ne!(
            base_quote.digest(),
            modified.digest(),
            "native_fee_estimate.max_fee_per_gas must affect digest"
        );

        let mut modified = base_quote.clone();
        modified.native_fee_estimate.max_priority_fee_per_gas = 20;
        assert_ne!(
            base_quote.digest(),
            modified.digest(),
            "native_fee_estimate.max_priority_fee_per_gas must affect digest"
        );

        test_field!(
            base_quote,
            authorization_address,
            Some(Address::repeat_byte(1)),
            "authorization_address must affect digest"
        );

        // Note: additional_authorization is tested via its presence/absence
        // and signature_hash(), which is tested separately

        test_field!(
            base_quote,
            orchestrator,
            Address::repeat_byte(1),
            "orchestrator must affect digest"
        );

        // fee_token_deficit and asset_deficits affect digest via has_deficits()
        test_field!(
            base_quote,
            fee_token_deficit,
            U256::from(100),
            "fee_token_deficit must affect digest"
        );

        // Verify intent changes affect digest
        let mut modified = base_quote.clone();
        modified.intent = modified.intent.with_eoa(Address::repeat_byte(1));
        assert_ne!(base_quote.digest(), modified.digest(), "intent must affect digest");
    }
}
