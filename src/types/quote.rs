//! Quote types.

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::{
    primitives::{Address, ChainId, Keccak256, PrimitiveSignature, B256, U256},
    providers::{utils::Eip1559Estimation as AlloyEip1559Estimation, Provider, WalletProvider},
};
use alloy_chains::Chain;
use futures_util::future::try_join_all;
use serde::{Deserialize, Serialize};

use crate::{
    types::{CoinKind, Signed, Token},
    upstream::Upstream,
};

/// A container of supported fee tokens per chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeTokens(
    #[serde(with = "alloy::serde::quantity::hashmap")] HashMap<ChainId, Vec<Token>>,
);

impl FeeTokens {
    /// Create a new [`FeeTokens`]
    pub async fn new<P>(tokens: &[Address], upstream: Upstream<P>) -> Result<Self, eyre::Error>
    where
        P: Provider + WalletProvider,
    {
        let upstream = Arc::new(upstream);
        let chain: Chain = upstream.chain_id().into();
        let fee_tokens = try_join_all(tokens.iter().copied().map(|token| {
            let upstream = upstream.clone();
            async move {
                let (decimals, coin_kind) = if token.is_zero() {
                    // todo: native is ETH for now
                    (18, CoinKind::ETH)
                } else {
                    (
                        upstream.get_token_decimals(token).await?,
                        CoinKind::get_token(chain, token).ok_or_else(|| {
                            eyre::eyre!("Token not supported: {token} @ {chain}.")
                        })?,
                    )
                };

                Ok::<_, eyre::Error>(Token::new(token, decimals, coin_kind))
            }
        }))
        .await?;

        Ok(Self(HashMap::from_iter([(upstream.chain_id(), fee_tokens)])))
    }

    /// Check if the fee token is supported on the given chain.
    pub fn contains(&self, chain_id: ChainId, fee_token: &Address) -> bool {
        self.0.get(&chain_id).is_some_and(|tokens| tokens.iter().any(|t| t.address == *fee_token))
    }

    /// Return a reference to a fee [`Token`] if supported on the given chain.
    pub fn find(&self, chain_id: ChainId, fee_token: &Address) -> Option<&Token> {
        self.0.get(&chain_id).and_then(|tokens| tokens.iter().find(|t| t.address == *fee_token))
    }
}

impl FromIterator<(ChainId, Vec<Token>)> for FeeTokens {
    fn from_iter<T: IntoIterator<Item = (ChainId, Vec<Token>)>>(iter: T) -> Self {
        Self(HashMap::from_iter(iter))
    }
}

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
    /// Add a signature turning the quote into a [`SignedQuote`].
    pub fn into_signed(self, signature: PrimitiveSignature) -> SignedQuote {
        let digest = self.digest();
        SignedQuote::new_unchecked(self, signature, digest)
    }

    /// Compute a digest of the quote for signing.
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
/// An EIP-1559 fee estimate.
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
