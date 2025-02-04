mod types;
use types::{BalanceCollector, LatencyCollector};

mod job;
use job::PeriodicJob;

use alloy::primitives::Address;
use std::{fmt::Debug, future::Future, time::Duration};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum MetricCollectorError {
    /// Error coming from RPC
    #[error(transparent)]
    RpcError(#[from] alloy::transports::RpcError<alloy::transports::TransportErrorKind>),
}

// Trait for a collector that records its own metric.
pub trait MetricCollector: Debug + Sync + 'static {
    /// Collects metrics and records them.
    fn collect(&self) -> impl Future<Output = Result<(), MetricCollectorError>> + Send;
}

/// Spawns all available periodic metric collectors.
pub fn spawn_periodic_collectors(signer: Address, endpoints: Vec<Url>) {
    PeriodicJob::launch_task(
        BalanceCollector { address: signer, endpoints: endpoints.clone() },
        tokio::time::interval(Duration::from_secs(5)),
    );

    PeriodicJob::launch_task(
        LatencyCollector { endpoints },
        tokio::time::interval(Duration::from_secs(5)),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::periodic::BalanceCollector;
    use alloy::primitives::{address, Address};
    use metrics_exporter_prometheus::PrometheusBuilder;
    use std::str::FromStr;
    use tokio::time::{self, Duration};
    use url::Url;

    #[ignore]
    #[tokio::test]
    async fn test_periodic_metrics_collection() {
        let handle = PrometheusBuilder::new().install_recorder().unwrap();
        let endpoints = vec![Url::from_str("http://localhost:8545").unwrap()];

        // Launches a periodic job on its own task
        {
            PeriodicJob::launch_task(
                BalanceCollector { address: Address::default(), endpoints: endpoints.clone() },
                tokio::time::interval(Duration::from_millis(500)),
            );
            PeriodicJob::launch_task(
                BalanceCollector {
                    address: address!("4242424242424242424242424242424242424242"),
                    endpoints: endpoints.clone(),
                },
                tokio::time::interval(Duration::from_millis(500)),
            );
            PeriodicJob::launch_task(
                LatencyCollector { endpoints: endpoints.clone() },
                tokio::time::interval(Duration::from_millis(500)),
            );
        }

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
