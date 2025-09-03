use std::time::Instant;

use alloy::{
    primitives::ChainId,
    rpc::json_rpc::{RequestPacket, ResponsePacket},
    transports::{TransportError, TransportFut},
};
use futures_util::FutureExt;
use metrics::histogram;
use opentelemetry::trace::SpanKind;
use tower::{Layer, Service};
use tracing::{Level, field, span};
use tracing_futures::Instrument;

/// A layer that wraps requests in spans with OpenTelemetry attributes.
///
/// The OpenTelemetry attributes adhere to the OpenTelemtry conventions.
///
/// See:
/// - <https://opentelemetry.io/docs/specs/semconv/rpc/json-rpc/>
/// - <https://opentelemetry.io/docs/specs/semconv/rpc/rpc-spans/>
#[derive(Debug, Clone)]
pub struct TraceLayer {
    chain_id: ChainId,
}

impl TraceLayer {
    /// Creates a new `TraceLayer` with the given `chain_id`.
    pub fn new(chain_id: ChainId) -> Self {
        Self { chain_id }
    }
}

impl<S> Layer<S> for TraceLayer {
    type Service = TraceTransport<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TraceTransport { inner, chain_id: self.chain_id }
    }
}

/// A trace-instrumented transport.
#[derive(Debug, Clone)]
pub struct TraceTransport<S> {
    inner: S,
    chain_id: ChainId,
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
        let chain_id = self.chain_id;
        let span = span!(
            Level::INFO,
            "call",
            otel.kind = ?SpanKind::Client,
            otel.name = field::Empty,
            rpc.jsonrpc.version = "2.0",
            rpc.system = "jsonrpc",
            rpc.jsonrpc.request_id = field::Empty,
            rpc.method = field::Empty,
            eth.chain_id = chain_id,
        );

        let mut method = None;

        // todo: what do we do with batches
        if let RequestPacket::Single(ref req) = request {
            span.record("otel.name", format!("alloy.transport/{}", req.method()));
            span.record("rpc.method", req.method());
            span.record("rpc.jsonrpc.request_id", req.id().to_string());

            method = Some(req.method().to_string());
        }

        let fut = self.inner.call(request);

        // todo: set `rpc.jsonrpc.error_code` and span status. this requires helpers in alloy to get
        // jsonrpc error codes from responses
        async move {
            let instant = Instant::now();
            let result = fut.await;
            let elapsed = instant.elapsed().as_millis() as f64;

            if let Some(method) = method {
                histogram!("node_latency", "chain_id" => chain_id.to_string(), "method" => method)
                    .record(elapsed);
            }

            result
        }
        .instrument(span)
        .boxed()
    }
}
