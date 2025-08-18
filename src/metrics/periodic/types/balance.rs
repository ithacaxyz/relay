use std::{fmt::Debug, sync::Arc};

use crate::{
    chains::Chains,
    metrics::periodic::{MetricCollector, MetricCollectorError},
};
use alloy::{primitives::Address, providers::Provider};
use metrics::gauge;

/// This collector queries a chain endpoint for balance of the signer.
#[derive(Debug)]
pub struct BalanceCollector {
    /// Addresses to be queried.
    addresses: Vec<Address>,
    /// Chains.
    chains: Arc<Chains>,
}

impl BalanceCollector {
    pub fn new(addresses: Vec<Address>, chains: Arc<Chains>) -> Self {
        Self { addresses, chains }
    }
}

impl MetricCollector for BalanceCollector {
    async fn collect(&self) -> Result<(), MetricCollectorError> {
        for address in &self.addresses {
            futures_util::future::try_join_all(self.chains.chains_iter().map(|chain| async move {
                chain.provider().get_balance(*address).await.inspect(|balance| {
                    gauge!(
                        "balance",
                        "address"  => address.to_checksum(Some(chain.id())),
                        "chain_id" => format!("{}", chain.id())
                    )
                    .set::<f64>(balance.into());
                })
            }))
            .await?;
        }
        Ok(())
    }
}
