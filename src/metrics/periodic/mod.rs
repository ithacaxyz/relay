mod types;
use types::{BalanceCollector, LatencyCollector};

mod job;
use job::PeriodicJob;

use alloy::{
    primitives::Address,
    providers::{DynProvider, Provider},
};
use std::{fmt::Debug, future::Future, time::Duration};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum MetricCollectorError {
    /// Error coming from RPC
    #[error(transparent)]
    RpcError(#[from] alloy::transports::RpcError<alloy::transports::TransportErrorKind>),
}

/// Trait for a collector that records its own metric.
pub trait MetricCollector: Debug {
    /// Collects metrics and records them.
    fn collect(&self) -> impl Future<Output = Result<(), MetricCollectorError>> + Send;
}

/// Spawns all available periodic metric collectors.
pub async fn spawn_periodic_collectors(
    signers: Vec<Address>,
    providers: Vec<DynProvider>,
    rpc_urls: Vec<Url>,
) -> Result<(), MetricCollectorError> {
    let mut providers_with_url = Vec::with_capacity(rpc_urls.len());
    let mut providers_with_chain = Vec::with_capacity(rpc_urls.len());

    for (provider, rpc) in providers.into_iter().zip(rpc_urls) {
        providers_with_chain.push((provider.get_chain_id().await?, provider.clone()));
        providers_with_url.push((rpc, provider));
    }

    PeriodicJob::launch_task(
        BalanceCollector::new(signers, providers_with_chain),
        tokio::time::interval(Duration::from_secs(5)),
    );

    PeriodicJob::launch_task(
        LatencyCollector::new(providers_with_url),
        tokio::time::interval(Duration::from_secs(5)),
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::{primitives::address, providers::ProviderBuilder};
    use metrics_exporter_prometheus::PrometheusBuilder;
    use tokio::time::{self, Duration};

    #[tokio::test]
    async fn test_periodic_metrics_collection() {
        let handle = PrometheusBuilder::new().install_recorder().unwrap();

        let provider = ProviderBuilder::new().disable_recommended_fillers().connect_anvil();

        let url = provider.anvil().endpoint_url();

        // Launches periodic jobs
        spawn_periodic_collectors(
            vec![address!("0x4242424242424242424242424242424242424242")],
            vec![provider.erased()],
            vec![url.clone()],
        )
        .await
        .unwrap();

        time::sleep(Duration::from_secs(3)).await;

        let metrics_output = handle.render();

        assert!(metrics_output.contains(
            "balance{address=\"0x4242424242424242424242424242424242424242\",chain_id=\"31337\"} 0"
        ));

        assert!(metrics_output.contains(format!("node_latency{{url=\"{url}\",quantile").as_str()));
    }
}
