//! Types for metrics.

mod periodic;
pub use periodic::spawn_periodic_collectors;

use futures_util::{future::BoxFuture, FutureExt, TryFutureExt};
use jsonrpsee::{
    server::{middleware::rpc::RpcServiceT, HttpBody, HttpRequest, HttpResponse},
    types::Request,
    MethodResponse,
};
use metrics::{counter, histogram};
use metrics_exporter_prometheus::PrometheusHandle;
use std::{future::Future, pin::Pin, time::Instant};
use tower::Service;
use tower_http::BoxError;

/// A Tower service that renders Prometheus metrics at `/metrics`.
#[derive(Debug, Clone)]
#[must_use]
pub struct MetricsService<S> {
    inner: S,
    recorder: PrometheusHandle,
}

impl<S> MetricsService<S> {
    /// Create a new metrics service with the given recorder handle.
    pub fn new(inner: S, recorder: PrometheusHandle) -> Self {
        Self { inner, recorder }
    }
}

impl<S, B> Service<HttpRequest<B>> for MetricsService<S>
where
    S: Service<HttpRequest, Response = HttpResponse>,
    S::Response: 'static,
    S::Error: Into<BoxError> + 'static,
    S::Future: Send + 'static,
    B: http_body::Body<Data = alloy::primitives::bytes::Bytes> + Send + 'static,
    B::Data: Send,
    B::Error: Into<BoxError>,
{
    type Response = S::Response;
    type Error = BoxError;
    type Future =
        Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'static>>;

    #[inline]
    fn poll_ready(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: HttpRequest<B>) -> Self::Future {
        if req.uri().path() == "/metrics" {
            let handle = self.recorder.clone();

            return async move {
                Ok(HttpResponse::builder()
                    .body(handle.render().into())
                    .expect("unable to parse response body"))
            }
            .boxed();
        }

        let req = req.map(HttpBody::new);
        self.inner.call(req).map_err(Into::into).boxed()
    }
}

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

impl<'a, S> RpcServiceT<'a> for RpcMetricsService<S>
where
    S: RpcServiceT<'a> + Send + Sync + Clone + 'static,
{
    type Future = BoxFuture<'a, MethodResponse>;

    fn call(&self, req: Request<'a>) -> Self::Future {
        let service = self.service.clone();

        Box::pin(async move {
            let method = req.method_name().to_string();

            let timer = Instant::now();
            let rp = service.call(req).await;
            let elapsed = timer.elapsed();

            counter!(
                "rpc.call.count",
                "method" => method.clone(),
                "code" => rp.as_error_code().unwrap_or_default().to_string()
            )
            .increment(1);

            histogram!(
                "rpc.call.latency","method" => method
            )
            .record(elapsed.as_millis() as f64);

            rp
        })
    }
}
