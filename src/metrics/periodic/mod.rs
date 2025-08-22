mod types;
use types::{BalanceCollector, LatencyCollector};

mod job;
use job::PeriodicJob;

use std::{fmt::Debug, future::Future, sync::Arc, time::Duration};

use crate::{
    chains::Chains, error::StorageError, metrics::periodic::types::LiquidityCollector,
    storage::RelayStorage,
};

#[derive(Debug, thiserror::Error)]
pub enum MetricCollectorError {
    /// Error coming from RPC
    #[error(transparent)]
    RpcError(#[from] alloy::transports::RpcError<alloy::transports::TransportErrorKind>),
    /// Error coming from storage
    #[error(transparent)]
    StorageError(#[from] StorageError),
}

/// Trait for a collector that records its own metric.
pub trait MetricCollector: Debug {
    /// Collects metrics and records them.
    fn collect(&self) -> impl Future<Output = Result<(), MetricCollectorError>> + Send;
}

/// Spawns all available periodic metric collectors.
pub async fn spawn_periodic_collectors(
    storage: RelayStorage,
    chains: Arc<Chains>,
) -> Result<(), MetricCollectorError> {
    PeriodicJob::launch_task(
        BalanceCollector::new(chains.clone()),
        tokio::time::interval(Duration::from_secs(30)),
    );

    PeriodicJob::launch_task(
        LiquidityCollector::new(storage, chains.clone()),
        tokio::time::interval(Duration::from_secs(30)),
    );

    PeriodicJob::launch_task(
        LatencyCollector::new(chains),
        tokio::time::interval(Duration::from_secs(30)),
    );

    Ok(())
}
