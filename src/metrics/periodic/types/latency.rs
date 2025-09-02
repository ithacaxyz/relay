use std::{sync::Arc, time::Instant};

use crate::{
    chains::Chains,
    metrics::periodic::{MetricCollector, MetricCollectorError},
};
use alloy::providers::Provider;
use metrics::histogram;
use std::fmt::Debug;

/// This collector measures the latency of each HTTP endpoint.
#[derive(Debug)]
pub struct LatencyCollector {
    /// Chains.
    chains: Arc<Chains>,
}

impl LatencyCollector {
    /// Create a new latency collector.
    pub fn new(chains: Arc<Chains>) -> Self {
        Self { chains }
    }
}

impl MetricCollector for LatencyCollector {
    async fn collect(&self) -> Result<(), MetricCollectorError> {
        for chain in self.chains.chains_iter() {
            let start = Instant::now();
            chain.provider().get_client_version().await?;
            let elapsed = start.elapsed().as_millis() as f64;

            histogram!(
                "node_latency",
                "chain_id" => format!("{}", chain.id()),
            )
            .record(elapsed);
        }

        Ok(())
    }
}
