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
