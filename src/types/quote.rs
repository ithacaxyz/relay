//! Quote types.

use std::{
    collections::HashMap,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use alloy::{
    primitives::{Address, B256, ChainId, Keccak256, PrimitiveSignature, U256},
    providers::{DynProvider, Provider, utils::Eip1559Estimation},
};
use futures_util::future::try_join_all;
use serde::{Deserialize, Serialize};

use crate::types::{CoinKind, Signed, Token};

use super::IERC20::IERC20Instance;

/// A container of supported fee tokens per chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeTokens(
    #[serde(with = "alloy::serde::quantity::hashmap")] HashMap<ChainId, Vec<Token>>,
);

impl FeeTokens {
    /// Create a new [`FeeTokens`]
    pub async fn new(tokens: &[Address], providers: Vec<DynProvider>) -> Result<Self, eyre::Error> {
        // todo: this is ugly
        let futs = providers
            .iter()
            .flat_map(|provider| tokens.iter().map(move |token| (provider, token)))
            .map(|(provider, token)| {
                async move {
                    let chain = provider.get_chain_id().await?;
                    let (decimals, coin_kind) = if token.is_zero() {
                        // todo: native is ETH for now
                        (18, CoinKind::ETH)
                    } else {
                        (
                            IERC20Instance::new(*token, provider).decimals().call().await?._0,
                            CoinKind::get_token(chain.into(), *token).ok_or_else(|| {
                                eyre::eyre!("Token not supported: {token} @ {chain}.")
                            })?,
                        )
                    };

                    Ok::<_, eyre::Error>((chain, Token::new(*token, decimals, coin_kind)))
                }
            });
        let fee_tokens = try_join_all(futs).await?;

        let mut map: HashMap<ChainId, Vec<Token>> = HashMap::default();
        for (chain_id, token) in fee_tokens.into_iter() {
            map.entry(chain_id).or_default().push(token);
        }

        Ok(Self(map))
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
        hasher.update(self.gas_estimate.to_be_bytes());
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
