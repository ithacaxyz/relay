//! The `onramp_` namespace.

use async_trait::async_trait;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

/// Ithaca `onramp_` RPC namespace.
#[rpc(server, client, namespace = "onramp")]
pub trait OnrampApi {
    /// Temporary
    #[method(name = "dummy")]
    async fn dummy(&self) -> RpcResult<()>;
}

/// Ithaca `onramp_` RPC module.
#[derive(Debug, Default)]
pub struct Onramp;

impl Onramp {
    /// Create a new onramp RPC module.
    pub fn new() -> Self {
        Default::default()
    }
}

#[async_trait]
impl OnrampApiServer for Onramp {
    async fn dummy(&self) -> RpcResult<()> {
        Ok(())
    }
}
