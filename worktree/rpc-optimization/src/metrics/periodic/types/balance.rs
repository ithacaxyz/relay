use std::fmt::Debug;

use crate::metrics::periodic::{MetricCollector, MetricCollectorError};
use alloy::{
    primitives::{Address, ChainId},
    providers::Provider,
};
use metrics::gauge;

/// This collector queries a chain endpoint for balance of the signer.
#[derive(Debug)]
pub struct BalanceCollector<P> {
    /// Addresses to be queried.
    addresses: Vec<Address>,
    /// Chains endpoints.
    providers_with_chain: Vec<(ChainId, P)>,
}

impl<P> BalanceCollector<P> {
    pub fn new(addresses: Vec<Address>, providers_with_chain: Vec<(ChainId, P)>) -> Self {
        Self { addresses, providers_with_chain }
    }
}

impl<P> MetricCollector for BalanceCollector<P>
where
    P: Provider + Debug,
{
    async fn collect(&self) -> Result<(), MetricCollectorError> {
        for address in &self.addresses {
            futures_util::future::try_join_all(self.providers_with_chain.iter().map(
                |(chain_id, provider)| async move {
                    provider.get_balance(*address).await.inspect(|balance| {
                        gauge!(
                            "balance",
                            "address"  => address.to_checksum(Some(*chain_id)),
                            "chain_id" => format!("{chain_id}")
                        )
                        .set::<f64>(balance.into());
                    })
                },
            ))
            .await?;
        }
        Ok(())
    }
}
