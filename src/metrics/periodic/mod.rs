mod types;
use types::{BalanceCollector, LatencyCollector};

mod job;
use job::PeriodicJob;

use alloy::primitives::Address;
use jsonrpsee::core::async_trait;
use std::{fmt::Debug, time::Duration};
use url::Url;

#[derive(Debug, thiserror::Error)]
pub enum MetricCollectorError {
    /// Error coming from RPC
    #[error(transparent)]
    RpcError(#[from] alloy::transports::RpcError<alloy::transports::TransportErrorKind>),
}

// Trait for a collector that records its own metric.
#[async_trait]
pub trait MetricCollector: Debug + Sync + 'static {
    /// Collects metrics and records them.
    async fn collect(&self) -> Result<(), MetricCollectorError>;
}

/// Spawns all available periodic metric collectors available.
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
    use crate::metrics::periodic::{job::PeriodicMetricJob, BalanceCollector};
    use alloy::primitives::{address, Address};
    use metrics_exporter_prometheus::PrometheusBuilder;
    use std::str::FromStr;
    use tokio::time::{Duration, Instant};
    use url::Url;

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
        }

        // Manually poll jobs one by one
        {
            let mut jobs: [Box<dyn PeriodicMetricJob>; 2] = [
                PeriodicJob::new_boxed(
                    BalanceCollector {
                        address: address!("4242424242424242424242424242424242424242"),
                        endpoints: endpoints.clone(),
                    },
                    tokio::time::interval(Duration::from_millis(500)),
                ),
                PeriodicJob::new_boxed(
                    LatencyCollector { endpoints: endpoints.clone() },
                    tokio::time::interval(Duration::from_millis(500)),
                ),
            ];

            // Run the scheduler loop for 3 seconds.
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                for job in jobs.iter_mut() {
                    job.advance().await;
                }
            }
        }

        let metrics_output = handle.render();

        assert!(metrics_output.contains(
            "balance{address=\"0x4242424242424242424242424242424242424242\",chain_id=\"1\"} 0"
        ));

        assert!(metrics_output.contains(
            "balance{address=\"0x0000000000000000000000000000000000000000\",chain_id=\"1\"} 0"
        ));
    }
}
