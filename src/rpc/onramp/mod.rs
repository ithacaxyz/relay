//! The `onramp_` namespace.

mod banxa;
mod mercuryo;

use async_trait::async_trait;
use http::{HeaderMap, HeaderValue, header::ACCEPT};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use serde::{Deserialize, Serialize};

use self::{banxa::BanxaProvider, mercuryo::MercuryoProvider};
use crate::{
    config::OnrampConfig,
    types::{
        OnrampOrder, OnrampOrderParameters, OnrampQuote, OnrampQuoteParameters, Order, OrderId,
    },
};

/// The provider to use for onramping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OnrampProvider {
    /// Use Mercuryo as the onramp provider.
    Mercuryo,
    /// Use Banxa as the onramp provider.
    Banxa,
}

/// Ithaca `onramp_` RPC namespace.
#[rpc(server, client, namespace = "onramp")]
pub trait OnrampApi {
    /// Get a quote from onramping providers.
    #[method(name = "getQuote")]
    async fn get_quote(
        &self,
        params: OnrampQuoteParameters,
        provider: Option<OnrampProvider>,
    ) -> RpcResult<OnrampQuote>;

    /// Get the status of an onramp order.
    #[method(name = "getOrderStatus")]
    async fn get_order_status(
        &self,
        order_id: OrderId,
        provider: Option<OnrampProvider>,
    ) -> RpcResult<Order>;

    /// Create onramp order
    #[method(name = "createOrder")]
    async fn create_order(
        &self,
        params: OnrampOrderParameters,
        provider: Option<OnrampProvider>,
    ) -> RpcResult<OnrampOrder>;
}

/// Ithaca `onramp_` RPC module.
#[derive(Debug)]
pub struct Onramp {
    #[allow(dead_code)]
    client: reqwest::Client,
    #[allow(dead_code)]
    config: OnrampConfig,
    banxa: BanxaProvider,
    mercuryo: MercuryoProvider,
}

impl Onramp {
    /// Create a new onramp RPC module.
    pub fn new(config: OnrampConfig) -> Self {
        let mut headers = HeaderMap::default();
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            // note: this is fatal and can only fail on boot
            .expect("could not build onramp client");

        let banxa = BanxaProvider::new(client.clone(), config.banxa.clone());
        let mercuryo = MercuryoProvider::new(client.clone(), config.mercuryo.clone());

        Self { client, config, banxa, mercuryo }
    }
}

#[async_trait]
impl OnrampApiServer for Onramp {
    // provider param has a default value of Mercuryo
    async fn get_quote(
        &self,
        params: OnrampQuoteParameters,
        provider: Option<OnrampProvider>,
    ) -> RpcResult<OnrampQuote> {
        // For now, default to Mercuryo. In the future, you could add logic here to:
        // - Select provider based on params (country, payment method, etc.)
        // - Try multiple providers and return the best quote
        // - Allow the client to specify preferred provider
        let provider = provider.unwrap_or(OnrampProvider::Mercuryo);

        match provider {
            OnrampProvider::Mercuryo => self.mercuryo.get_quote(params).await,
            OnrampProvider::Banxa => self.banxa.get_quote(params).await,
        }
    }

    async fn get_order_status(
        &self,
        order_id: OrderId,
        provider: Option<OnrampProvider>,
    ) -> RpcResult<Order> {
        // For now, default to Mercuryo. In the future, you could:
        // - Parse the order_id to determine which provider it belongs to
        // - Store provider info with the order in your database
        // - Try multiple providers until one recognizes the order_id
        let provider = provider.unwrap_or(OnrampProvider::Mercuryo);

        match provider {
            OnrampProvider::Mercuryo => self.mercuryo.get_order_status(order_id).await,
            OnrampProvider::Banxa => self.banxa.get_order_status(order_id).await,
        }
    }

    async fn create_order(
        &self,
        params: OnrampOrderParameters,
        provider: Option<OnrampProvider>,
    ) -> RpcResult<OnrampOrder> {
        let provider = provider.unwrap_or(OnrampProvider::Mercuryo);
        match provider {
            OnrampProvider::Mercuryo => self.mercuryo.create_order(params).await,
            OnrampProvider::Banxa => self.banxa.create_order(params).await,
        }
    }
}
