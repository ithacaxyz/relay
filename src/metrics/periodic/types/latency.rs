use std::time::Instant;

use crate::metrics::periodic::{MetricCollector, MetricCollectorError};
use alloy::providers::Provider;
use metrics::histogram;
use std::fmt::Debug;
use url::Url;

/// This collector measures the latency of each HTTP endpoint.
pub struct LatencyCollector<P> {
    /// Chains endpoints.
    providers_with_url: Vec<(Url, P)>,
}

impl<P> LatencyCollector<P> {
    pub fn new(providers_with_url: Vec<(Url, P)>) -> Self {
        Self { providers_with_url }
    }
}

impl<P> MetricCollector for LatencyCollector<P>
where
    P: Provider + Debug,
{
    async fn collect(&self) -> Result<(), MetricCollectorError> {
        for (url, provider) in &self.providers_with_url {
            let start = Instant::now();
            provider.get_client_version().await?;
            let elapsed = start.elapsed().as_millis() as f64;

            histogram!(
                "node_latency",
                "url" => format!("{url}"),
            )
            .record(elapsed);
        }

        Ok(())
    }
}

impl<P> Debug for LatencyCollector<P>
where
    P: Provider,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let urls: Vec<&Url> = self.providers_with_url.iter().map(|(url, _)| url).collect();
        f.debug_struct("BalanceCollector").field("providers", &urls).finish()
    }
}
