//! Timeout layer for RPC requests.

use alloy::{
    primitives::ChainId,
    rpc::json_rpc::{RequestPacket, ResponsePacket},
    transports::{Transport, TransportError, TransportErrorKind, TransportFut},
};
use futures::FutureExt;
use std::{
    task::{Context, Poll},
    time::Duration,
};
use tower::{Layer, Service};
use tracing::warn;

/// A [`tower::Layer`] that adds a timeout to requests.
#[derive(Debug, Clone)]
pub struct TimeoutLayer {
    timeout: Duration,
    chain_id: ChainId,
}

impl TimeoutLayer {
    /// Create a new [`TimeoutLayer`] with the given timeout duration and chain ID.
    pub const fn new(timeout: Duration, chain_id: ChainId) -> Self {
        Self { timeout, chain_id }
    }
}

impl<T> Layer<T> for TimeoutLayer {
    type Service = TimeoutService<T>;

    fn layer(&self, inner: T) -> Self::Service {
        TimeoutService { inner, timeout: self.timeout, chain_id: self.chain_id }
    }
}

/// A service that wraps another service with a timeout.
#[derive(Debug, Clone)]
pub struct TimeoutService<T> {
    inner: T,
    timeout: Duration,
    chain_id: ChainId,
}

impl<T> Service<RequestPacket> for TimeoutService<T>
where
    T: Transport + Clone,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        let method = req.as_single().map(|r| r.method()).unwrap_or("unknown").to_string();

        let fut = self.inner.call(req);
        let timeout = self.timeout;
        let chain_id = self.chain_id;

        async move {
            match tokio::time::timeout(timeout, fut).await {
                Ok(result) => result,
                Err(_) => {
                    warn!(
                        %chain_id,
                        %method,
                        timeout_secs = timeout.as_secs(),
                        "RPC request timeout"
                    );
                    Err(TransportErrorKind::custom_str(&format!(
                        "request timeout: chain_id={}, method={}",
                        chain_id, method
                    )))
                }
            }
        }
        .boxed()
    }
}
