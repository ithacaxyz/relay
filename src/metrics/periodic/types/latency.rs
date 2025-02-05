use std::{marker::PhantomData, time::Instant};

use crate::metrics::periodic::{MetricCollector, MetricCollectorError};
use alloy::{providers::Provider, transports::Transport};
use metrics::histogram;
use std::fmt::Debug;
use url::Url;

/// This collector measures the latency of each HTTP endpoint.
pub struct LatencyCollector<P, T> {
    /// Chains endpoints.
    providers_with_url: Vec<(Url, P)>,
    _transport: PhantomData<T>,
}

impl<P: Debug, T> LatencyCollector<P, T> {
    pub fn new(providers_with_url: Vec<(Url, P)>) -> Self {
        Self { providers_with_url, _transport: Default::default() }
    }
}

impl<P, T> MetricCollector for LatencyCollector<P, T>
where
    P: Provider<T> + Debug,
    T: Transport + Clone,
{
    async fn collect(&self) -> Result<(), MetricCollectorError> {
        for (url, provider) in &self.providers_with_url {
            let start = Instant::now();
            provider.get_client_version().await?;
            let elapsed = start.elapsed().as_millis() as f64;

            histogram!(
                "latency",
                "url" => format!("{url}"),
            )
            .record(elapsed);
        }

        Ok(())
    }
}

impl<P, T> Debug for LatencyCollector<P, T>
where
    P: Provider<T>,
    T: Transport + Clone,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let urls: Vec<&Url> = self.providers_with_url.iter().map(|(url, _)| url).collect();
        f.debug_struct("BalanceCollector").field("providers", &urls).finish()
    }
}
