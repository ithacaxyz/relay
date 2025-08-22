//! Types for metrics.

mod periodic;
use futures::{FutureExt, future::BoxFuture};
use http::Response;
use opentelemetry::{propagation::TextMapPropagator, trace::SpanKind};
use opentelemetry_http::HeaderInjector;
use opentelemetry_sdk::propagation::TraceContextPropagator;
pub use periodic::spawn_periodic_collectors;

mod transport;
use tower::Service;
use tracing::{Level, span};
use tracing_futures::Instrument;
use tracing_opentelemetry::OpenTelemetrySpanExt;
pub use transport::*;

use jsonrpsee::{
    MethodResponse,
    core::{BoxError, middleware::Batch},
    server::{HttpBody, HttpRequest, HttpResponse, middleware::rpc::RpcServiceT},
    types::{Notification, Request},
};
use metrics::{counter, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::{
    borrow::Cow,
    net::SocketAddr,
    pin::Pin,
    sync::Mutex,
    task::{Context, Poll},
    time::{Duration, Instant},
};

/// A [`jsonrpsee`] RPC middleware that records metrics for RPC methods.
#[derive(Debug, Clone)]
pub struct RpcMetricsService<S> {
    service: S,
}

impl<S> RpcMetricsService<S> {
    /// Create a new RPC middleware that records metrics for RPC methods.
    pub fn new(inner: S) -> Self {
        Self { service: inner }
    }
}

impl<S> RpcServiceT for RpcMetricsService<S>
where
    S: RpcServiceT<MethodResponse = MethodResponse> + Send + Sync + Clone + 'static,
{
    type MethodResponse = S::MethodResponse;
    type NotificationResponse = S::NotificationResponse;
    type BatchResponse = S::BatchResponse;

    fn call<'a>(&self, req: Request<'a>) -> impl Future<Output = Self::MethodResponse> + Send + 'a {
        let service = self.service.clone();

        async move {
            let method = req.method_name().replace("wallet_", "relay_");
            let span = span!(
                Level::INFO,
                "request",
                otel.kind = ?SpanKind::Server,
                otel.name = format!("relay/{}", method),
                rpc.jsonrpc.version = "2.0",
                rpc.system = "jsonrpc",
                rpc.jsonrpc.request_id = %req.id(),
                rpc.method = method,
                // Will be filled in implementation, if possible.
                eth.chain_id = tracing::field::Empty,
            );

            // the span handle is cloned here so we can record more fields later
            let timer = Instant::now();
            let mut rp = service.call(req).instrument(span.clone()).await;
            let elapsed = timer.elapsed();

            // Insert the span context for consuming later in `HttpTracingService`.
            rp.extensions_mut().insert(span.context());

            if let Some(error_code) = rp.as_error_code() {
                span.record("rpc.jsonrpc.error_code", error_code);

                // only record metrics for methods that exist
                if error_code != jsonrpsee::types::error::METHOD_NOT_FOUND_CODE {
                    counter!(
                        "rpc.call.count",
                        "method" => method.clone(),
                        "code" => rp.as_error_code().unwrap_or_default().to_string()
                    )
                    .increment(1);

                    histogram!(
                        "rpc.call.latency",
                        "method" => method
                    )
                    .record(elapsed.as_millis() as f64);
                }
            }

            rp
        }
    }

    fn batch<'a>(
        &self,
        requests: Batch<'a>,
    ) -> impl Future<Output = Self::BatchResponse> + Send + 'a {
        // todo(onbjerg): this is assuming no one uses batching right now which might be ok
        self.service.batch(requests)
    }

    fn notification<'a>(
        &self,
        n: Notification<'a, Option<Cow<'a, serde_json::value::RawValue>>>,
    ) -> impl Future<Output = Self::NotificationResponse> + Send + 'a {
        // todo(onbjerg): this is assuming no notifications - we don't have these right now, so
        // that's okay
        self.service.notification(n)
    }
}

/// HTTP middleware that records trace context for responses.
#[derive(Debug, Clone)]
pub struct HttpTracingService<S> {
    inner: S,
}

impl<S> HttpTracingService<S> {
    /// Create a new HTTP middleware that records trace context for responses.
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S, B> Service<HttpRequest<B>> for HttpTracingService<S>
where
    S: Service<HttpRequest<B>, Response = HttpResponse<HttpBody>>,
    S::Error: Into<BoxError>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future = BoxFuture<'static, Result<Self::Response, Self::Error>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, request: HttpRequest<B>) -> Self::Future {
        let fut = self.inner.call(request);
        async move {
            let mut rp = fut.await.map_err(Into::into)?;
            // We expect the span context to be inserted by the `RpcMetricsService`.
            if let Some(ctx) = rp.extensions().get::<opentelemetry::Context>().cloned() {
                TraceContextPropagator::new()
                    .inject_context(&ctx, &mut HeaderInjector(rp.headers_mut()));
            }
            Ok(rp)
        }
        .boxed()
    }
}

/// Builds a Prometheus exporter, returning a handle.
///
/// The recorder will perform upkeep every 5 seconds.
///
/// # Panics
///
/// This will panic if the Prometheus recorder could not be set as the global metrics recorder.
pub async fn setup_exporter(metrics_addr: impl Into<SocketAddr>) -> PrometheusHandle {
    static HANDLE: Mutex<Option<PrometheusHandle>> = Mutex::new(None);

    let mut lock = HANDLE.lock().unwrap();
    if let Some(handle) = &*lock {
        return handle.clone();
    }

    let addr: SocketAddr = metrics_addr.into();
    let (recorder, exporter) = PrometheusBuilder::new()
        .with_http_listener(addr)
        .upkeep_timeout(Duration::from_secs(5))
        .build()
        .expect("failed to build metrics recorder");

    let handle = recorder.handle();
    metrics::set_global_recorder(recorder).expect("could not set metrics recorder");
    tokio::spawn(exporter);

    tracing::info!(target: "relay::spawn", %addr, "Started metrics server");

    *lock = Some(handle.clone());

    handle
}
