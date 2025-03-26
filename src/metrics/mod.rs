//! Types for metrics.

mod periodic;
pub use periodic::spawn_periodic_collectors;

use futures_util::future::BoxFuture;
use jsonrpsee::{MethodResponse, server::middleware::rpc::RpcServiceT, types::Request};
use metrics::{counter, histogram};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle};
use std::{
    net::SocketAddr,
    sync::Mutex,
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

            // only record metrics for methods that exist
            if rp
                .as_error_code()
                .is_none_or(|code| code != jsonrpsee::types::error::METHOD_NOT_FOUND_CODE)
            {
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

            rp
        })
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
