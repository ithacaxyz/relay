//! Periodic metric collectors.

mod types;
pub use types::*;

mod job;
use job::PeriodicJob;

use std::{fmt::Debug, future::Future, sync::Arc, time::Duration};

use crate::{chains::Chains, config::RelayConfig, error::StorageError, storage::RelayStorage};

/// Metric collector error.
#[derive(Debug, thiserror::Error)]
pub enum MetricCollectorError {
    /// Error coming from RPC
    #[error(transparent)]
    RpcError(#[from] alloy::transports::RpcError<alloy::transports::TransportErrorKind>),
    /// Error coming from storage
    #[error(transparent)]
    StorageError(#[from] StorageError),
    /// Multicall error.
    #[error(transparent)]
    MulticallError(#[from] alloy::providers::MulticallError),
}

/// Trait for a collector that records its own metric.
pub trait MetricCollector: Debug {
    /// Collects metrics and records them.
    fn collect(&self) -> impl Future<Output = Result<(), MetricCollectorError>> + Send;
}

/// Spawns all available periodic metric collectors.
pub async fn spawn_periodic_collectors(
    config: &RelayConfig,
    storage: RelayStorage,
    chains: Arc<Chains>,
) -> Result<(), MetricCollectorError> {
    PeriodicJob::launch_task(
        BalanceCollector::new(config.funder, chains.clone()),
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
