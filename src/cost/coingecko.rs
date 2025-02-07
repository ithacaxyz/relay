#![allow(unused)]
use crate::{error::EstimateFeeError, types::Token};
use alloy::{
    primitives::{Address, U256},
    providers::utils::Eip1559Estimation,
};
use reqwest::get;
use serde_json::Value;
use std::{collections::HashMap, time::Duration};
use tokio::{sync::watch, time::interval};
use tracing::{error, info, trace};

/// Cost estimator that uses `CoinGecko` for a price feed.
#[derive(Debug, Default, Clone)]
pub struct CoinGecko {
    /// Token prices against ETH(wei).
    token_prices: HashMap<Address, watch::Receiver<Option<u128>>>,
}

impl CoinGecko {
    /// Creates an instance of [`CoinGecko`] that receives a price feed for all tokens from a
    /// spawned task every 10 seconds.
    pub fn new(tokens: &[Address]) -> Self {
        let mut tx_map = HashMap::with_capacity(tokens.len());
        let mut rx_map = HashMap::with_capacity(tokens.len());

        for token in tokens {
            let (tx, rx) = watch::channel(None);
            rx_map.insert(*token, rx);

            // Coingecko handles addresses in lowercase.
            tx_map.insert(token.to_string().to_lowercase(), tx);
        }

        // Coingecko receives the list of tokens separated by commas
        let tokens_split_by_comma =
            tokens.iter().map(|t| t.to_string()).collect::<Vec<_>>().join(",");

        // Launch task to fetch prices every 10 seconds
        tokio::spawn(async move {
            let mut clock = interval(Duration::from_secs(10));
            loop {
                clock.tick().await;
                if let Err(err) = Self::update_prices(&tokens_split_by_comma, &tx_map).await {
                    error!(?err);
                }
                clock.reset();
            }
        });

        Self { token_prices: rx_map }
    }

    /// Returns token price in ETH(wei).
    async fn update_prices(
        tokens_split_by_comma: &str,
        tokens_price_feed: &HashMap<String, watch::Sender<Option<u128>>>,
    ) -> Result<(), EstimateFeeError> {
        let url = format!(
            "https://api.coingecko.com/api/v3/simple/token_price/ethereum?contract_addresses={}&vs_currencies=eth&x_cg_demo_api_key={}",
            tokens_split_by_comma,
            std::env::var("GECKO_API").unwrap_or_default()
        );

        // Fetch token price in ETH
        let resp = get(&url)
            .await
            .map_err(|err| EstimateFeeError::InternalError(err.into()))?
            .text()
            .await
            .map_err(|err| EstimateFeeError::InternalError(err.into()))?;

        trace!(response=?resp);

        let json_resp: Value = serde_json::from_str(&resp)
            .map_err(|err| EstimateFeeError::InternalError(err.into()))?;

        for (token, sender) in tokens_price_feed {
            if let Some(token_price_in_eth) =
                json_resp.get(token).and_then(|v| v.get("eth")).and_then(|v| v.as_f64())
            {
                let _ = sender.send(Some((token_price_in_eth * 1e18) as u128));
            } else {
                error!("Could not get price for token {token}");
            }
        }

        Ok(())
    }
}

impl super::CostEstimate for CoinGecko {
    async fn eth_price(&self, payment_token: &Address) -> Result<u128, EstimateFeeError> {
        // SAFETY: borrow should not deadlock since the value is sent from a dedicated thread.
        if let Some(token_price_in_wei) =
            self.token_prices.get(payment_token).and_then(|a| *a.borrow())
        {
            return Ok(token_price_in_wei);
        }

        Err(EstimateFeeError::CostEstimateError(
            "could not find token price to calculate gas cost.".to_string(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cost::CostEstimate;
    use alloy::primitives::address;
    use tokio::time::sleep;

    #[ignore] // requires GECKO_API
    #[tokio::test]
    async fn coingecko() {
        let gas_price = 3_500_000_000u128;
        let usdt = Token::new(address!("dac17f958d2ee523a2206206994597c13d831ec7"), 6);
        let usdc = Token::new(address!("a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"), 6);
        let gecko = CoinGecko::new(&[usdt.address, usdc.address]);

        // Waits for coingecko calls to succeed.
        sleep(Duration::from_millis(500)).await;

        gecko.estimate(&usdt, gas_price).await.unwrap();
        gecko.estimate(&usdc, gas_price).await.unwrap();
    }
}
