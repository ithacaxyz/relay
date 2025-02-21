use alloy::{
    rpc::json_rpc::{RequestPacket, ResponsePacket},
    transports::{TransportError, TransportFut},
};
use futures_util::FutureExt;
use tower::{Layer, Service};
use tracing::{Level, field, span};
use tracing_futures::Instrument;

/// A layer that adds additional span information to requests on a given transport.
#[derive(Debug, Clone)]
pub struct TraceLayer;

impl<S> Layer<S> for TraceLayer {
    type Service = TraceTransport<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TraceTransport { inner }
    }
}

/// A trace-instrumented transport.
#[derive(Debug, Clone)]
pub struct TraceTransport<S> {
    inner: S,
}

impl<S> Service<RequestPacket> for TraceTransport<S>
where
    S: Service<RequestPacket, Future = TransportFut<'static>, Error = TransportError>
        + Send
        + 'static
        + Clone,
{
    type Response = ResponsePacket;
    type Error = TransportError;
    type Future = TransportFut<'static>;

    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: RequestPacket) -> Self::Future {
        let span = span!(Level::INFO, "call", rpc.method = field::Empty);

        // todo: what do we do with batches
        if let RequestPacket::Single(ref req) = request {
            span.record("rpc.method", req.method());
        }

        self.inner.call(request).instrument(span).boxed()
    }
}
