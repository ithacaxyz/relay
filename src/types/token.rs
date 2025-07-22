use crate::types::{CoinKind, CoinRegistry, IERC20::IERC20Instance};
use alloy::{
    primitives::{
        Address, ChainId, U256,
        map::{HashMap, HashSet},
    },
    providers::{DynProvider, Provider},
};
use futures_util::future::try_join_all;
use serde::{Deserialize, Serialize};
use tokio::try_join;

/// Token type with its address, decimals and [`CoinKind`].
#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Token {
    /// Token address.
    pub address: Address,
    /// Token decimals.
    pub decimals: u8,
    /// Token symbol as defined in the contract.
    pub symbol: String,
    /// Coin kind.
    pub kind: CoinKind,
    /// Rate of 1 whole token against the native chain token, expressed in the native token's
    /// smallest indivisible unit.
    ///
    /// # Examples
    /// - USDC decimals: 6
    /// - ETH decimals: 18
    ///
    /// 1. **USDC on Ethereum**
    ///    - 1 USDC = 0.000628 ETH ⇒   `native_rate = 0.000628 * 10^18 = 628_000_000_000_000 Wei`
    /// 2. **Stablecoin chain where USDC _is_ the native token**
    ///    - 1 USDC = 1 USDC ⇒   `native_rate = 1 * 10^6 = 1_000_000`
    pub native_rate: Option<U256>,
    /// Whether this token is supported for interop.
    pub interop: bool,
}

impl Token {
    /// Create a new instance of [`Self`].
    pub fn new(
        address: Address,
        decimals: u8,
        symbol: String,
        kind: CoinKind,
        interop: bool,
    ) -> Self {
        Self { address, decimals, kind, symbol, native_rate: None, interop }
    }

    /// Sets a native price rate.
    pub fn with_rate(mut self, native_rate: U256) -> Self {
        self.native_rate = Some(native_rate);
        self
    }
}

/// A container of supported fee tokens per chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeTokens(
    #[serde(with = "alloy::serde::quantity::hashmap")] HashMap<ChainId, Vec<Token>>,
);

impl FeeTokens {
    /// Create a new [`FeeTokens`]
    pub async fn new(
        coin_registry: &CoinRegistry,
        fee_tokens: &[Address],
        interop_tokens: &[Address],
        providers: Vec<DynProvider>,
    ) -> Result<Self, eyre::Error> {
        // todo: this is ugly
        let futs = providers
            .iter()
            .flat_map(|provider| fee_tokens.iter().map(move |token| (provider, token)))
            .map(|(provider, token)| {
                async move {
                    let interop = interop_tokens.contains(token);
                    let chain = provider.get_chain_id().await?;
                    let ((decimals, symbol), coin_kind) = if token.is_zero() {
                        // todo: native is ETH for now
                        ((18, "ETH".to_string()), CoinKind::ETH)
                    } else {
                        let erc20 = IERC20Instance::new(*token, provider);
                        let decimals = erc20.decimals();
                        let symbol = erc20.symbol();

                        let Some(coin_kind) = CoinKind::get_token(coin_registry, chain, *token)
                        else {
                            return Ok(None);
                        };

                        (try_join!(decimals.call(), symbol.call())?, coin_kind)
                    };

                    Ok::<_, eyre::Error>(Some((
                        chain,
                        Token::new(*token, decimals, symbol, coin_kind, interop),
                    )))
                }
            });
        let fee_tokens = try_join_all(futs).await?;

        // Collect into a set first to make sure we don't have duplicates
        let mut map: HashMap<ChainId, HashSet<Token>> = HashMap::default();
        for (chain_id, token) in fee_tokens.into_iter().flatten() {
            map.entry(chain_id).or_default().insert(token);
        }

        Ok(Self(
            map.into_iter()
                .map(|(chain_id, token_set)| (chain_id, token_set.into_iter().collect()))
                .collect(),
        ))
    }

    /// Check if the fee token is supported on the given chain.
    pub fn contains(&self, chain_id: ChainId, fee_token: &Address) -> bool {
        self.0.get(&chain_id).is_some_and(|tokens| tokens.iter().any(|t| t.address == *fee_token))
    }

    /// Return a reference to a fee [`Token`] if supported on the given chain.
    pub fn find(&self, chain_id: ChainId, fee_token: &Address) -> Option<&Token> {
        self.0.get(&chain_id).and_then(|tokens| tokens.iter().find(|t| t.address == *fee_token))
    }

    /// Return an iterator over all tokens per chain.
    pub fn iter(&self) -> impl Iterator<Item = (&ChainId, &Vec<Token>)> {
        self.0.iter()
    }

    /// Return a reference to all chain tokens.
    pub fn chain_tokens(&self, chain_id: ChainId) -> Option<&Vec<Token>> {
        self.0.get(&chain_id)
    }
}

impl FromIterator<(ChainId, Vec<Token>)> for FeeTokens {
    fn from_iter<T: IntoIterator<Item = (ChainId, Vec<Token>)>>(iter: T) -> Self {
        Self(HashMap::from_iter(iter))
    }
}
