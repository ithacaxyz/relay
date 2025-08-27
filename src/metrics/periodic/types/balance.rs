use std::{fmt::Debug, sync::Arc};

use crate::{
    chains::Chains,
    metrics::periodic::{MetricCollector, MetricCollectorError, types::format_units_f64},
};
use alloy::providers::Provider;
use futures_util::StreamExt;
use metrics::gauge;
use tracing::error;

/// This collector queries a chain endpoint for balance of the signers per chain.
#[derive(Debug)]
pub struct BalanceCollector {
    /// Chains.
    chains: Arc<Chains>,
}

impl BalanceCollector {
    /// Create a new balance collector.
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
                        let (symbol, decimals) = chain
                            .native_symbol()
                            .zip(chain.assets().native().map(|(_, asset)| asset.decimals))
                            .unwrap_or(("ETH", 18));

                        match format_units_f64(*balance, decimals) {
                            Ok(balance) => gauge!(
                                "balance",
                                "address" => signer_addr.to_checksum(Some(chain.id())),
                                "chain_id" => chain.id().to_string(),
                                "symbol" => symbol.to_string(),
                            )
                            .set::<f64>(balance),
                            Err(err) => error!(?balance, ?err, "Failed to format balance"),
                        }
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
