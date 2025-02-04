mod types;
use types::{BalanceCollector, LatencyCollector};

mod job;
use job::PeriodicJob;

use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    rpc::client::RpcClient,
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
    signer: Address,
    rpc_urls: Vec<Url>,
) -> Result<(), MetricCollectorError> {
    let mut providers_with_url = Vec::with_capacity(rpc_urls.len());
    let mut providers_with_chain = Vec::with_capacity(rpc_urls.len());

    for rpc in rpc_urls {
        let provider = ProviderBuilder::new()
            .with_recommended_fillers()
            .on_client(RpcClient::new_http(rpc.clone()).boxed());

        providers_with_chain.push((provider.get_chain_id().await?, provider.clone()));
        providers_with_url.push((rpc, provider));
    }

    PeriodicJob::launch_task(
        BalanceCollector::new(signer, providers_with_chain),
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
    use alloy::primitives::address;
    use metrics_exporter_prometheus::PrometheusBuilder;
    use std::str::FromStr;
    use tokio::time::{self, Duration};
    use url::Url;

    #[ignore]
    #[tokio::test]
    async fn test_periodic_metrics_collection() {
        let handle = PrometheusBuilder::new().install_recorder().unwrap();

        // Launches periodic jobs
        spawn_periodic_collectors(
            address!("4242424242424242424242424242424242424242"),
            vec![Url::from_str("http://localhost:8545").unwrap()],
        )
        .await
        .unwrap();

        time::sleep(Duration::from_secs(3)).await;

        let metrics_output = handle.render();

        assert!(metrics_output.contains(
            "balance{address=\"0x4242424242424242424242424242424242424242\",chain_id=\"1\"} 0"
        ));

        assert!(metrics_output.contains(
            "balance{address=\"0x0000000000000000000000000000000000000000\",chain_id=\"1\"} 0"
        ));

        assert!(metrics_output.contains("latency{url=\"http://localhost:8545/\",quantile"));
    }
}
