//! The `onramp_` namespace.

use async_trait::async_trait;
use http::{HeaderMap, HeaderValue, header::ACCEPT};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

use crate::{
    error::RelayError,
    types::{OnrampQuote, OnrampQuoteParameters, banxa},
};

/// Ithaca `onramp_` RPC namespace.
#[rpc(server, client, namespace = "onramp")]
pub trait OnrampApi {
    /// Get a quote from onramping providers.
    #[method(name = "getQuote")]
    async fn get_quote(&self, params: OnrampQuoteParameters) -> RpcResult<OnrampQuote>;
}

/// Ithaca `onramp_` RPC module.
#[derive(Debug, Default)]
pub struct Onramp {
    client: reqwest::Client,
}

impl Onramp {
    /// Create a new onramp RPC module.
    pub fn new() -> Self {
        let mut headers = HeaderMap::default();
        // todo: api key
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        Self {
            client: reqwest::Client::builder()
                .default_headers(headers)
                .build()
                // note: this is fatal and can only fail on boot
                .expect("could not build onramp client"),
        }
    }
}

#[async_trait]
impl OnrampApiServer for Onramp {
    async fn get_quote(&self, params: OnrampQuoteParameters) -> RpcResult<OnrampQuote> {
        let quote: banxa::BuyQuote = self
            .client
            .get("https://api.banxa-sandbox.com/porto/v2/quotes/buy")
            .query(&[("paymentMethodId", params.payment_method)])
            .query(&[("crypto", params.crypto_currency)])
            .query(&[("fiat", params.fiat_currency)])
            .query(&[("cryptoAmount", params.target_amount)])
            .query(&[
                // todo: we need to be able to configure this
                ("blockchain", "BASE"),
            ])
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
