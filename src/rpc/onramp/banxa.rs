//! Banxa onramp provider implementation.

use jsonrpsee::core::RpcResult;

use crate::{
    config::BanxaConfig,
    error::RelayError,
    types::{
        OnrampOrder, OnrampOrderParameters, OnrampQuote, OnrampQuoteParameters, Order, OrderId,
        banxa,
    },
};

/// Banxa onramp provider.
#[derive(Debug)]
pub struct BanxaProvider {
    client: reqwest::Client,
    config: BanxaConfig,
}

impl BanxaProvider {
    /// Create a new Banxa provider.
    pub fn new(client: reqwest::Client, config: BanxaConfig) -> Self {
        Self { client, config }
    }

    /// Create a request builder for Banxa API calls with authentication.
    fn request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        let mut request = self.client.request(method, url);

        // Add API key header if configured
        if !self.config.secrets.api_key.is_empty() {
            request = request.header("X-Api-Key", &self.config.secrets.api_key);
        }

        request
    }

    /// Get a quote from Banxa.
    pub async fn get_quote(&self, params: OnrampQuoteParameters) -> RpcResult<OnrampQuote> {
        let url = format!("{}/porto/v2/quotes/buy", self.config.api_url);
        let quote: banxa::BuyQuote = self
            .request(reqwest::Method::GET, &url)
            .query(&[("paymentMethodId", params.payment_method)])
            .query(&[("crypto", params.crypto_currency)])
            .query(&[("fiat", params.fiat_currency)])
            .query(&[("cryptoAmount", params.target_amount)])
            .query(&[("blockchain", &self.config.blockchain)])
            .send()
            .await
            .map_err(RelayError::from)?
            .json()
            .await
            .map_err(RelayError::from)?;

        Ok(OnrampQuote {
            fiat_amount: quote.fiat_amount,
            fiat_currency: params.fiat_currency,
            crypto_amount: quote.crypto_amount,
            crypto_currency: params.crypto_currency,
            exchange_rate: quote.fiat_amount / quote.crypto_amount,
            fees: quote.network_fee + quote.processing_fee,
        })
    }

    /// Get order status from Banxa.
    pub async fn get_order_status(&self, order_id: OrderId) -> RpcResult<Order> {
        let url = format!("{}/porto/v2/orders/{order_id}", self.config.api_url);
        let order: banxa::Order = self
            .request(reqwest::Method::GET, &url)
            .send()
            .await
            .map_err(RelayError::from)?
            .json()
            .await
            .map_err(RelayError::from)?;

        Ok(Order { order_id, status: order.status.into(), tx_hash: order.transaction_hash })
    }

    /// Create an order from Banxa.
    #[allow(dead_code)]
    pub async fn create_order(&self, _params: OnrampOrderParameters) -> RpcResult<OnrampOrder> {
        todo!("Banxa order creation implementation pending")
    }
}
