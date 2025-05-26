//! The `onramp_` namespace.

use async_trait::async_trait;
use http::{HeaderMap, HeaderValue, header::ACCEPT};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

use crate::{
    config::OnrampConfig,
    error::RelayError,
    types::{OnrampQuote, OnrampQuoteParameters, Order, OrderId, banxa},
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

        // Add API key header if configured
        if !config.banxa.secrets.api_key.is_empty() {
            if let Ok(header_value) = HeaderValue::from_str(&config.banxa.secrets.api_key) {
                headers.insert("X-Api-Key", header_value);
            }
        }

        Self {
            client: reqwest::Client::builder()
                .default_headers(headers)
                .build()
                // note: this is fatal and can only fail on boot
                .expect("could not build onramp client"),
            config,
        }
    }
}

#[async_trait]
impl OnrampApiServer for Onramp {
    async fn get_quote(&self, params: OnrampQuoteParameters) -> RpcResult<OnrampQuote> {
        let url = format!("{}/porto/v2/quotes/buy", self.config.banxa.api_url);
        let quote: banxa::BuyQuote = self
            .client
            .get(&url)
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

    async fn get_order_status(&self, order_id: OrderId) -> RpcResult<Order> {
        let url = format!("{}/porto/v2/orders/{order_id}", self.config.banxa.api_url);
        let order: banxa::Order = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(RelayError::from)?
            .json()
            .await
            .map_err(RelayError::from)?;

        Ok(Order { order_id, status: order.status.into(), tx_hash: order.transaction_hash })
    }
}
