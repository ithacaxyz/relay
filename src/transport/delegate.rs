//! Delegate transport implementation that fans out requests to multiple services.

use crate::transport::ETH_SEND_RAW_TRANSACTION;
use alloy::{
    rpc::json_rpc::{RequestPacket, ResponsePacket},
    transports::{TransportError, TransportFut},
};
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::task::{Context, Poll, ready};
use tower::{Layer, Service};
use tracing::error;

/// A [`tower::Layer`] responsible for delegating `eth_sendRawTransaction` requests.
#[derive(Debug, Clone)]
pub struct EthSendRawDelegateLayer<S> {
    raw_delegate: S,
    allow_regular_fallback: bool,
}

impl<S> EthSendRawDelegateLayer<S> {
    /// Create a new [`EthSendRawDelegateLayer`].
    pub fn new(raw_delegate: S) -> Self {
        Self { raw_delegate, allow_regular_fallback: true }
    }

    /// Whether or not to fallback to the regular transport
    pub fn allow_fallback(&mut self, allow: bool) -> &mut Self {
        self.allow_regular_fallback = allow;
        self
    }
}

impl<T, M: Clone> Layer<T> for EthSendRawDelegateLayer<M> {
    type Service = EthSendRawDelegateService<T, M>;

    fn layer(&self, inner: T) -> Self::Service {
        EthSendRawDelegateService {
            inner,
            raw_delegate: self.raw_delegate.clone(),
            allow_regular_fallback: self.allow_regular_fallback,
        }
    }
}

/// A [`alloy::transports::Transport`] that combines two transports.
///
/// All `eth_sendRawTransaction` requests will be delegated to the configured service
#[derive(Debug, Clone)]
pub struct EthSendRawDelegateService<R, D> {
    /// The regular transport
    inner: R,
    /// The service to delegate `eth_sendRawTransaction` to
    raw_delegate: D,
    /// Whether to fallback to the regular service in case the raw service failed.
    allow_regular_fallback: bool,
}

impl<R, D> Service<RequestPacket> for EthSendRawDelegateService<R, D>
where
    R: Service<
            RequestPacket,
            Response = ResponsePacket,
            Error = TransportError,
            Future = TransportFut<'static>,
        > + Send
        + Clone
        + 'static,
    D: Service<
            RequestPacket,
            Response = ResponsePacket,
            Error = TransportError,
            Future = TransportFut<'static>,
        >,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Both services must be ready
        ready!(self.inner.poll_ready(cx))?;
        self.raw_delegate.poll_ready(cx)
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        if req.as_single().is_some_and(|r| r.method() == ETH_SEND_RAW_TRANSACTION) {
            // Note: we must only create the fallback future on demand
            let fallback = self.allow_regular_fallback.then(|| (self.inner.clone(), req.clone()));
            let delegate = self.raw_delegate.call(req);
            return Box::pin(async move {
                let mut res = delegate.await;
                // we only fallback in the error transport case, but not the error RPC case to avoid
                // leaking the transaction in case it resulted in an RPC error
                if res.is_err()
                    && let Some((mut fallback, req)) = fallback
                {
                    error!("All eth_sendRawTransaction delegates failed, falling back to regular");
                    res = fallback.call(req).await;
                }
                res
            });
        }

        self.inner.call(req)
    }
}

/// A service that sends requests to multiple services and returns the first successful
/// response, but ensures all requests are delivered.
#[derive(Debug, Clone)]
pub struct MulticastService<S> {
    services: Vec<S>,
}

impl<S> MulticastService<S> {
    /// Creates a new instance with the given services.
    pub fn new(services: Vec<S>) -> Self {
        assert!(!services.is_empty(), "Multicast requires at least one service");
        MulticastService { services }
    }
}

impl<S> Service<RequestPacket> for MulticastService<S>
where
    S: Service<
            RequestPacket,
            Response = ResponsePacket,
            Error = TransportError,
            Future = TransportFut<'static>,
        >,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        for service in &mut self.services {
            ready!(service.poll_ready(cx))?;
        }
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        let mut futs = self
            .services
            .iter_mut()
            .map(|service| service.call(request.clone()))
            .collect::<FuturesUnordered<_>>();

        Box::pin(async move {
            // obtain the first result
            let mut res = futs.next().await.expect("has at least one service");

            // we still want to deliver to all endpoints
            while let Some(next) = futs.next().await {
                // here we want to filter for the success case, both transport and actual rpc
                // response
                if res.is_err() || res.as_ref().is_ok_and(|resp| resp.is_error()) {
                    res = next;
                }
            }

            res
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        primitives::B256,
        rpc::json_rpc::{Id, Request, Response, ResponsePayload, SerializedRequest},
    };
    use serde_json::value::RawValue;
    use std::{
        future::poll_fn,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    /// Helper function that transforms a closure to a transport service
    fn request_fn<T>(f: T) -> RequestFn<T>
    where
        T: FnMut(RequestPacket) -> TransportFut<'static>,
    {
        RequestFn { f }
    }

    #[derive(Clone)]
    struct RequestFn<T> {
        f: T,
    }

    impl<T> Service<RequestPacket> for RequestFn<T>
    where
        T: FnMut(RequestPacket) -> TransportFut<'static>,
    {
        type Response = ResponsePacket;
        type Error = TransportError;
        type Future = TransportFut<'static>;

        fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), TransportError>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, req: RequestPacket) -> Self::Future {
            (self.f)(req)
        }
    }

    fn make_hash_response() -> ResponsePacket {
        ResponsePacket::Single(Response {
            id: Id::Number(0),
            payload: ResponsePayload::Success(
                RawValue::from_string(serde_json::to_string(&B256::ZERO).unwrap()).unwrap(),
            ),
        })
    }

    fn make_error_response() -> TransportError {
        TransportError::local_usage_str("test error")
    }

    #[tokio::test]
    async fn test_multicast_service_error_fallback() {
        let counter = Arc::new(AtomicUsize::new(0));

        // Test that we fallback to successful responses when first response is an error
        let counter1 = counter.clone();
        let mut multicast =
            MulticastService::new(vec![request_fn(move |_request: RequestPacket| {
                let count = counter1.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move {
                    // First call returns error
                    if count == 0 {
                        Err::<ResponsePacket, _>(make_error_response())
                    } else {
                        Ok::<_, TransportError>(make_hash_response())
                    }
                })
            })]);

        let request = Request::new("test_method", Id::Number(0), ("0x00".to_string(),));
        let packet = RequestPacket::from(SerializedRequest::try_from(request).unwrap());

        // First call should return error
        let resp = multicast.call(packet.clone()).await;
        assert!(resp.is_err());
        assert_eq!(counter.load(Ordering::SeqCst), 1);

        // Second call should succeed
        let _resp = multicast.call(packet).await.unwrap();
        assert_eq!(counter.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_eth_send_raw_multicast_routing() {
        let (tx_raw, mut rx_raw) = tokio::sync::mpsc::unbounded_channel();
        let (tx_regular, mut rx_regular) = tokio::sync::mpsc::unbounded_channel();

        // Service for eth_sendRawTransaction
        let raw_service = request_fn(move |request: RequestPacket| {
            let tx = tx_raw.clone();
            Box::pin(async move {
                tx.send(request).unwrap();
                Ok::<_, TransportError>(make_hash_response())
            })
        });

        // Regular service for other methods
        let regular_service = request_fn(move |request: RequestPacket| {
            let tx = tx_regular.clone();
            Box::pin(async move {
                tx.send(request).unwrap();
                Ok::<_, TransportError>(make_hash_response())
            })
        });

        let layer = EthSendRawDelegateLayer::new(raw_service);
        let mut service = layer.layer(regular_service);

        // Test eth_sendRawTransaction routing
        let request = Request::new(ETH_SEND_RAW_TRANSACTION, Id::Number(0), ("0x00".to_string(),));
        let packet = RequestPacket::from(SerializedRequest::try_from(request).unwrap());

        let _resp = service.call(packet).await.unwrap();

        // Should have received on raw service channel
        let _ = rx_raw.recv().await.unwrap();

        // Regular service should not have received anything
        poll_fn(|cx| {
            assert!(rx_regular.poll_recv(cx).is_pending());
            Poll::Ready(())
        })
        .await;

        // Test regular method routing
        let request = Request::new("eth_getBlockByNumber", Id::Number(1), ("latest", false));
        let packet = RequestPacket::from(SerializedRequest::try_from(request).unwrap());

        let _resp = service.call(packet).await.unwrap();

        // Should have received on regular service channel
        let _ = rx_regular.recv().await.unwrap();

        // Raw service should not receive more requests
        poll_fn(|cx| {
            assert!(rx_raw.poll_recv(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }

    #[tokio::test]
    async fn test_eth_send_raw_multicast_with_fallback() {
        let counter = Arc::new(AtomicUsize::new(0));

        // Raw service that fails
        let raw_service = request_fn(move |_request: RequestPacket| {
            Box::pin(async move { Err::<ResponsePacket, _>(make_error_response()) })
        });

        // Regular service that succeeds
        let regular_service = {
            let counter = counter.clone();
            request_fn(move |_request: RequestPacket| {
                counter.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move { Ok::<_, TransportError>(make_hash_response()) })
            })
        };

        let mut layer = EthSendRawDelegateLayer::new(raw_service);
        layer.allow_fallback(true);
        let mut service = layer.layer(regular_service);

        // Test eth_sendRawTransaction with fallback
        let request = Request::new(ETH_SEND_RAW_TRANSACTION, Id::Number(0), ("0x00".to_string(),));
        let packet = RequestPacket::from(SerializedRequest::try_from(request).unwrap());

        let _resp = service.call(packet).await.unwrap();

        // Regular service should have been called as fallback
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_eth_send_raw_with_multicast_service() {
        // Test combining EthSendRawMulticast with MulticastService
        let raw_counter = Arc::new(AtomicUsize::new(0));
        let regular_counter = Arc::new(AtomicUsize::new(0));

        // Create a multicast service for raw transactions that counts calls
        let raw_counter_clone = raw_counter.clone();
        let raw_multicast =
            MulticastService::new(vec![request_fn(move |_request: RequestPacket| {
                // This single service simulates multiple endpoints
                raw_counter_clone.fetch_add(1, Ordering::SeqCst);
                Box::pin(async move { Ok::<_, TransportError>(make_hash_response()) })
            })]);

        // Create a service for regular requests
        let reg_counter_clone = regular_counter.clone();
        let regular_service = request_fn(move |_request: RequestPacket| {
            reg_counter_clone.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok::<_, TransportError>(make_hash_response()) })
        });

        // Combine them with EthSendRawMulticast
        let layer = EthSendRawDelegateLayer::new(raw_multicast);
        let mut service = layer.layer(regular_service);

        // Test eth_sendRawTransaction - should go to raw multicast
        let raw_request =
            Request::new(ETH_SEND_RAW_TRANSACTION, Id::Number(0), ("0xdeadbeef".to_string(),));
        let raw_packet = RequestPacket::from(SerializedRequest::try_from(raw_request).unwrap());

        let _resp = service.call(raw_packet).await.unwrap();

        // Raw service should have been called
        assert_eq!(raw_counter.load(Ordering::SeqCst), 1);
        // Regular service should not have been called
        assert_eq!(regular_counter.load(Ordering::SeqCst), 0);

        // Test regular method - should go to regular service
        let regular_request = Request::new("eth_blockNumber", Id::Number(1), ());
        let regular_packet =
            RequestPacket::from(SerializedRequest::try_from(regular_request).unwrap());

        let _resp = service.call(regular_packet).await.unwrap();

        // Raw service should still be at 1
        assert_eq!(raw_counter.load(Ordering::SeqCst), 1);
        // Regular service should have been called
        assert_eq!(regular_counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_eth_send_raw_multicast_with_failing_multicast() {
        // Test fallback when the raw multicast service fails
        let counter = Arc::new(AtomicUsize::new(0));

        // Create a raw multicast that always fails
        let raw_multicast =
            MulticastService::new(vec![request_fn(move |_request: RequestPacket| {
                Box::pin(async move { Err::<ResponsePacket, _>(make_error_response()) })
            })]);

        // Regular service that succeeds
        let reg_counter = counter.clone();
        let regular_service = request_fn(move |_request: RequestPacket| {
            reg_counter.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move { Ok::<_, TransportError>(make_hash_response()) })
        });

        // Enable fallback
        let mut layer = EthSendRawDelegateLayer::new(raw_multicast);
        layer.allow_fallback(true);
        let mut service = layer.layer(regular_service);

        // Test eth_sendRawTransaction with fallback
        let request = Request::new(ETH_SEND_RAW_TRANSACTION, Id::Number(0), ("0x00".to_string(),));
        let packet = RequestPacket::from(SerializedRequest::try_from(request).unwrap());

        let _resp = service.call(packet).await.unwrap();

        // Regular service should have been called as fallback
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }
}
