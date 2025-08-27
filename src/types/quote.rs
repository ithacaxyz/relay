//! Quote types.

use crate::{
    error::{QuoteError, RelayError},
    types::{Intent, Intents, Signed},
};
use alloy::{
    primitives::{Address, B256, ChainId, Keccak256, Sealable, Signature, U256},
    providers::{DynProvider, utils::Eip1559Estimation},
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
}

impl Quotes {
    /// Sets the merkle payload to every quote.
    pub async fn with_merkle_payload(
        mut self,
        providers: Vec<DynProvider>,
    ) -> Result<Self, RelayError> {
        if self.quotes.len() != providers.len() {
            return Err(QuoteError::InvalidNumberOfIntents {
                expected: providers.len(),
                got: self.quotes.len(),
            }
            .into());
        }

        let mut intents = Intents::new(
            self.quotes
                .iter()
                .zip(providers)
                .map(|(quote, provider)| (quote.intent.clone(), provider, quote.orchestrator))
                .collect(),
        );

        self.multi_chain_root = Some(intents.root().await?);

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
    /// Orchestrator to use for the transaction.
    pub orchestrator: Address,
    /// How much of the fee token the user is missing to pay for this intent.
    ///
    /// If it is 0, the user has enough balance to execute the call.
    #[serde(default)]
    pub fee_token_deficit: U256,
}

impl Quote {
    /// Compute a digest of the quote for signing.
    pub fn digest(&self) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update(self.chain_id.to_be_bytes());
        if let Some(address) = self.authorization_address {
            hasher.update(address);
        }
        hasher.update(self.intent.digest());
        hasher.update(self.orchestrator);
        hasher.finalize()
    }
}
