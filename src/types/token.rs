use super::{CoinKind, IERC20::IERC20Instance};
use alloy::{
    primitives::{Address, ChainId, map::HashMap},
    providers::{DynProvider, Provider},
};
use futures_util::future::try_join_all;
use serde::{Deserialize, Serialize};

/// Token type with its address, decimals and [`CoinKind`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// Token address.
    pub address: Address,
    /// Token decimals.
    pub decimals: u8,
    /// Coin kind.
    pub coin: CoinKind,
}

impl Token {
    /// Create a new instance of [`Self`].
    pub fn new(address: Address, decimals: u8, coin: CoinKind) -> Self {
        Self { address, decimals, coin }
    }
}

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
