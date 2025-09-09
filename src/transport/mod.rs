//! L2 Transport implementation with `eth_sendRawTransaction` forwarding.

use alloy::{
    providers::WsConnect,
    pubsub::PubSubConnect,
    rpc::{
        client::BuiltInConnectionString,
        json_rpc::{RequestPacket, ResponsePacket},
    },
    transports::{
        BoxTransport, Transport, TransportConnect, TransportError, TransportFut, TransportResult,
        layers::RetryBackoffLayer,
    },
};
use futures_util::{StreamExt, stream::FuturesUnordered};
use std::{
    str::FromStr,
    task::{Context, Poll, ready},
};
use tower::{Layer, Service};
use url::Url;

pub mod delegate;
pub mod error;

const ETH_SEND_RAW_TRANSACTION: &str = "eth_sendRawTransaction";

/// [`RetryBackoffLayer`] used for chain providers.
///
/// We are allowing max 10 retries with a backoff of 800ms. The CU/s is set to max value to avoid
/// any throttling.
pub const RETRY_LAYER: RetryBackoffLayer = RetryBackoffLayer::new(10, 800, u64::MAX);

/// A [`tower::Layer`] responsible for forwarding transactions to sequencer.
#[derive(Debug, Clone)]
pub struct SequencerLayer<S> {
    sequencer: S,
}

impl<S> SequencerLayer<S> {
    /// Create a new [`SequencerLayer`].
    pub fn new(sequencer: S) -> Self {
        Self { sequencer }
    }
}

impl<T, S: Clone> Layer<T> for SequencerLayer<S> {
    type Service = SequencerService<T, S>;

    fn layer(&self, inner: T) -> Self::Service {
        SequencerService { inner, sequencer: self.sequencer.clone() }
    }
}

/// A [`alloy::transports::Transport`] that combines two transports.
/// And also forwards requests for `eth_sendRawTransaction` to the sequencer service.
///
/// This exclusively forwards `eth_sendRawTransaction` because it is assumed that this is the only
/// endpoint that is whitelisted by the sequencer server.
#[derive(Debug, Clone)]
pub struct SequencerService<T, S> {
    /// The regular transport
    inner: T,
    /// The transport to route requests to the sequencer.
    sequencer: S,
}

impl<T, S> SequencerService<T, S> {
    /// Creates a new instance of the [`SequencerService`].
    pub const fn new(inner: T, sequencer: S) -> SequencerService<T, S> {
        SequencerService { sequencer, inner }
    }

    /// Configures the regular transport
    pub fn with_transport<U>(self, inner: U) -> SequencerService<U, S> {
        SequencerService { sequencer: self.sequencer, inner }
    }

    /// Configures the regular transport
    pub fn with_sequencer<U>(self, sequencer: U) -> SequencerService<T, U> {
        SequencerService { inner: self.inner, sequencer }
    }
}

impl Default for SequencerService<(), ()> {
    fn default() -> Self {
        Self { sequencer: (), inner: () }
    }
}

impl<T, S> Service<RequestPacket> for SequencerService<T, S>
where
    T: Transport,
    S: Transport,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        // Both services must be ready
        ready!(self.inner.poll_ready(cx))?;
        self.sequencer.poll_ready(cx)
    }

    fn call(&mut self, req: RequestPacket) -> Self::Future {
        if req.as_single().is_some_and(|r| r.method() == ETH_SEND_RAW_TRANSACTION) {
            // This is raw transaction submission that we want to also route to the sequencer
            let mut futures = FuturesUnordered::new();
            futures.push(self.sequencer.call(req.clone()));
            futures.push(self.inner.call(req));
            return Box::pin(async move {
                let mut first_error = None;
                while let Some(output) = futures.next().await {
                    if output.as_ref().map(|resp| resp.as_error().is_some()).unwrap_or(true) {
                        // If first request already failed, return the error we got from it
                        // because it's likely more informative
                        if let Some(resp) = first_error {
                            return resp;
                        } else {
                            // Otherwise, remember the error and await the next response
                            first_error = Some(output);
                        }
                    } else {
                        return output;
                    }
                }

                unreachable!()
            });
        }

        self.inner.call(req)
    }
}

/// Creates a [`BoxTransport`] from a [`Url`].
///
/// Returns the transport and a boolean indicating if the transport is local.
pub async fn create_transport(url: &Url) -> TransportResult<(BoxTransport, bool)> {
    let url = BuiltInConnectionString::from_str(url.as_str())?;
    let is_local = url.is_local();

    let transport = match url {
        BuiltInConnectionString::Ws(url, auth) => WsConnect::new(url.as_str())
            .with_auth_opt(auth)
            // Configure max number of retries to prevent provider from becoming useless
            .with_max_retries(u32::MAX)
            .into_service()
            .await?
            .boxed(),
        _ => url.connect_boxed().await?,
    };

    Ok((transport, is_local))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{
        primitives::B256,
        rpc::json_rpc::{Id, Request, Response, ResponsePayload, SerializedRequest},
    };
    use serde_json::value::RawValue;
    use std::future::poll_fn;

    /// Helper function that transforms a closure to a alloy transport service
    fn request_fn<T>(f: T) -> RequestFn<T>
    where
        T: FnMut(RequestPacket) -> TransportFut<'static>,
    {
        RequestFn { f }
    }

    #[derive(Copy, Clone)]
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
            Ok(()).into()
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

    #[tokio::test]
    async fn test_raw_tx_forwarding_service() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let sequencer_transport = request_fn(move |request: RequestPacket| {
            let tx = tx.clone();
            Box::pin(async move {
                tx.send(request).unwrap();
                Ok::<_, TransportError>(make_hash_response())
            })
        });

        let regular_transport = request_fn(|_request: RequestPacket| {
            Box::pin(async move { Ok::<_, TransportError>(make_hash_response()) })
        });

        let mut service = SequencerService::default()
            .with_transport(regular_transport)
            .with_sequencer(sequencer_transport);

        let request = Request::new(ETH_SEND_RAW_TRANSACTION, Id::Number(0), ("0x00".to_string(),));
        let packet = RequestPacket::from(SerializedRequest::try_from(request).unwrap());

        let _resp = service.call(packet).await.unwrap();

        // received raw tx request through sequencer transport
        let _ = rx.recv().await.unwrap();

        let request = Request::new("not_raw", Id::Number(0), ("0x00".to_string(),));
        let packet = RequestPacket::from(SerializedRequest::try_from(request).unwrap());

        let _resp = service.call(packet).await.unwrap();

        poll_fn(|cx| {
            assert!(rx.poll_recv(cx).is_pending());
            Poll::Ready(())
        })
        .await;
    }
}
