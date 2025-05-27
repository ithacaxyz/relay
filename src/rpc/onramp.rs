//! The `onramp_` namespace.

use async_trait::async_trait;
use http::{HeaderMap, HeaderValue, header::ACCEPT};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

use crate::{
    config::OnrampConfig,
    error::RelayError,
    types::{
        OnrampOrder, OnrampOrderParameters, OnrampQuote, OnrampQuoteParameters, Order, OrderId,
        banxa, mercuryo,
    },
};

/// Ithaca `onramp_` RPC namespace.
#[rpc(server, client, namespace = "onramp")]
pub trait OnrampApi {
    /// Get a quote from onramping providers.
    #[method(name = "getQuote")]
    async fn get_quote(&self, params: OnrampQuoteParameters) -> RpcResult<OnrampQuote>;

    /// Get the status of an onramp order.
    #[method(name = "getOrderStatus")]
    async fn get_order_status(&self, order_id: OrderId) -> RpcResult<Order>;

    /// Create onramp order
    #[method(name = "createOrder")]
    async fn create_order(&self, params: OnrampOrderParameters) -> RpcResult<OnrampOrder>;
}

/// Ithaca `onramp_` RPC module.
#[derive(Debug)]
pub struct Onramp {
    client: reqwest::Client,
    config: OnrampConfig,
}

impl Onramp {
    /// Create a new onramp RPC module.
    pub fn new(config: OnrampConfig) -> Self {
        let mut headers = HeaderMap::default();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        Self {
            client: reqwest::Client::builder()
                .default_headers(headers)
                .build()
                // note: this is fatal and can only fail on boot
                .expect("could not build onramp client"),
            config,
        }
    }

    /// Create a request builder for Mercuryo API calls with authentication.
    fn mercuryo_request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        let mut request = self.client.request(method, url);

        // Add API key header if configured
        if !self.config.mercuryo.secrets.api_key.is_empty() {
            request = request.header("Sdk-Partner-Token", &self.config.mercuryo.secrets.api_key);
        }

        request
    }

    /// Get a quote from Mercuryo.
    async fn get_quote_mercuryo(&self, params: OnrampQuoteParameters) -> RpcResult<OnrampQuote> {
        let url = format!("{}/widget/buy/rate", self.config.mercuryo.api_url);
        let quote: mercuryo::BuyQuote = self
            .mercuryo_request(reqwest::Method::GET, &url)
            .query(&[("from", params.crypto_currency)])
            .query(&[("to", params.fiat_currency)])
            .query(&[("transaction_type", "buy")])
            .query(&[("is_total", "true")])
            .query(&[("network", &self.config.mercuryo.blockchain)])
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

    /// Get order status from Banxa.
    async fn _get_order_status_banxa(&self, order_id: OrderId) -> RpcResult<Order> {
        let url = format!("{}/porto/v2/orders/{order_id}", self.config.banxa.api_url);
        let order: banxa::Order = self
            ._banxa_request(reqwest::Method::GET, &url)
            .send()
            .await
            .map_err(RelayError::from)?
            .json()
            .await
            .map_err(RelayError::from)?;

        Ok(Order { order_id, status: order.status.into(), tx_hash: order.transaction_hash })
    }

    /// Get order status from Mercuryo.
    #[allow(dead_code)]
    async fn get_order_status_mercuryo(&self, _order_id: OrderId) -> RpcResult<Order> {
        todo!("Mercuryo order status implementation pending")
    }

    /// Create an order from Mercuryo.
    #[allow(dead_code)]
    async fn create_order_mercuryo(
        &self,
        _params: OnrampOrderParameters,
    ) -> RpcResult<OnrampOrder> {
        todo!("Mercuryo order creation implementation pending")
    }

    /// Create a request builder for Banxa API calls with authentication.
    fn _banxa_request(&self, method: reqwest::Method, url: &str) -> reqwest::RequestBuilder {
        let mut request = self.client.request(method, url);

        // Add API key header if configured
        if !self.config.banxa.secrets.api_key.is_empty() {
            request = request.header("X-Api-Key", &self.config.banxa.secrets.api_key);
        }

        request
    }

    /// Get a quote from Banxa.
    async fn _get_quote_banxa(&self, params: OnrampQuoteParameters) -> RpcResult<OnrampQuote> {
        let url = format!("{}/porto/v2/quotes/buy", self.config.banxa.api_url);
        let quote: banxa::BuyQuote = self
            ._banxa_request(reqwest::Method::GET, &url)
            .query(&[("paymentMethodId", params.payment_method)])
            .query(&[("crypto", params.crypto_currency)])
            .query(&[("fiat", params.fiat_currency)])
            .query(&[("cryptoAmount", params.target_amount)])
            .query(&[("blockchain", &self.config.banxa.blockchain)])
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
}

#[async_trait]
impl OnrampApiServer for Onramp {
    async fn get_quote(&self, params: OnrampQuoteParameters) -> RpcResult<OnrampQuote> {
        // For now, default to Mercuryo. In the future, you could add logic here to:
        // - Select provider based on params (country, payment method, etc.)
        // - Try multiple providers and return the best quote
        // - Allow the client to specify preferred provider

        self.get_quote_mercuryo(params).await
    }

    async fn get_order_status(&self, order_id: OrderId) -> RpcResult<Order> {
        // For now, default to Mercuryo. In the future, you could:
        // - Parse the order_id to determine which provider it belongs to
        // - Store provider info with the order in your database
        // - Try multiple providers until one recognizes the order_id

        self.get_order_status_mercuryo(order_id).await
    }

    async fn create_order(&self, _params: OnrampOrderParameters) -> RpcResult<OnrampOrder> {
        todo!("Onramp order creation implementation pending")
    }
}
