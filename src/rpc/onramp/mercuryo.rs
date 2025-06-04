//! Mercuryo onramp provider implementation.

use jsonrpsee::core::RpcResult;

use crate::{
    config::MercuryoConfig,
    error::RelayError,
    types::{
        OnrampOrder, OnrampOrderParameters, OnrampQuote, OnrampQuoteParameters, Order, OrderId,
        mercuryo,
    },
};

/// Mercuryo onramp provider.
#[derive(Debug)]
pub struct MercuryoProvider {
    client: reqwest::Client,
    config: MercuryoConfig,
}

impl MercuryoProvider {
    /// Create a new Mercuryo provider.
    pub fn new(client: reqwest::Client, config: MercuryoConfig) -> Self {
        Self { client, config }
    }

    /// Create a request builder for Mercuryo API calls with authentication.
    fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        let mut request = self.client.request(method, url);

        // Add API key header if configured
        if !self.config.secrets.api_key.is_empty() {
            request = request.header("Sdk-Partner-Token", &self.config.secrets.api_key);
        }

        request
    }

    /// Get a quote from Mercuryo.
    pub async fn get_quote(&self, params: OnrampQuoteParameters) -> RpcResult<OnrampQuote> {
        let url = format!("{}/widget/buy/rate", self.config.api_url);
        let quote: mercuryo::BuyQuote = self
            .request(reqwest::Method::GET, &url)
            .query(&[("from", params.crypto_currency)])
            .query(&[("to", params.fiat_currency)])
            .query(&[("transaction_type", "buy")])
            .query(&[("is_total", "true")])
            .query(&[("network", &self.config.blockchain)])
            .send()
            .await
            .map_err(RelayError::from)?
            .json()
            .await
            .map_err(RelayError::from)?;

        Ok(OnrampQuote {
            fiat_amount: quote.fiat_amount.parse::<f32>().unwrap(),
            fiat_currency: params.fiat_currency,
            crypto_amount: quote.amount.parse::<f32>().unwrap(),
            crypto_currency: params.crypto_currency,
            exchange_rate: quote.fiat_amount.parse::<f32>().unwrap()
                / quote.amount.parse::<f32>().unwrap(),
            fees: quote.fee.values().map(|v| v.parse::<f32>().unwrap()).sum(),
        })
    }

    /// Get order status from Mercuryo.
    #[allow(dead_code)]
    pub async fn get_order_status(&self, _order_id: OrderId) -> RpcResult<Order> {
        todo!("Mercuryo order status implementation pending")
    }

    /// Create an order from Mercuryo.
    #[allow(dead_code)]
    pub async fn create_order(&self, _params: OnrampOrderParameters) -> RpcResult<OnrampOrder> {
        todo!("Mercuryo order creation implementation pending")
    }
}
