use std::time::Instant;

use crate::metrics::periodic::{MetricCollector, MetricCollectorError};
use alloy::{
    providers::{Provider, ProviderBuilder},
    rpc::client::RpcClient,
};
use jsonrpsee::core::async_trait;
use metrics::histogram;
use url::Url;

// This collector measures the latency of each HTTP endpoint.
#[derive(Debug)]
pub struct LatencyCollector {
    pub endpoints: Vec<Url>,
}

#[async_trait]
impl MetricCollector for LatencyCollector {
    async fn collect(&self) -> Result<(), MetricCollectorError> {
        for endpoint in &self.endpoints {
            let provider = ProviderBuilder::new()
                .with_recommended_fillers()
                .on_client(RpcClient::new_http(endpoint.clone()).boxed());

            let start = Instant::now();
            provider.get_client_version().await?;
            let elapsed = start.elapsed().as_millis() as f64;

            histogram!(
                "latency",
                "url" => format!("{endpoint}"),
            )
            .record(elapsed);
        }

        Ok(())
    }
}
