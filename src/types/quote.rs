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
        if let Some(address) = self.authorization_address {
            hasher.update(address);
        }
        if let Some(auth) = &self.additional_authorization {
            hasher.update(auth.signature_hash());
        }
        hasher.update(self.intent.digest());
        hasher.update(self.orchestrator);
        hasher.update([self.has_deficits() as u8]);
        hasher.finalize()
    }
}
