use std::{fmt::Debug, sync::Arc};

use crate::{
    chains::Chains,
    metrics::periodic::{MetricCollector, MetricCollectorError},
};
use alloy::providers::Provider;
use futures_util::StreamExt;
use metrics::gauge;

/// This collector queries a chain endpoint for balance of the signers per chain.
#[derive(Debug)]
pub struct BalanceCollector {
    /// Chains.
    chains: Arc<Chains>,
}

impl BalanceCollector {
    pub fn new(chains: Arc<Chains>) -> Self {
        Self { chains }
    }
}

impl MetricCollector for BalanceCollector {
    async fn collect(&self) -> Result<(), MetricCollectorError> {
        // we process them buffered to avoid sending out bursts
        let mut requests = Vec::with_capacity(self.chains.total_signers());
        for chain in self.chains.chains_iter() {
            for signer_addr in chain.signer_addresses() {
                requests.push(async move {
                    chain.provider().get_balance(signer_addr).await.inspect(|balance| {
                        gauge!(
                            "balance",
                            "address"  => signer_addr.to_checksum(Some(chain.id())),
                            "chain_id" => format!("{}", chain.id())
                        )
                        .set::<f64>(balance.into())
                    })
                })
            }
        }
        futures::stream::iter(requests)
            .buffered(self.chains.len())
            .for_each(|_| futures::future::ready(()))
            .await;

        Ok(())
    }
}
