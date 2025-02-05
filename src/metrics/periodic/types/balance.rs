use std::fmt::Debug;

use crate::metrics::periodic::{MetricCollector, MetricCollectorError};
use alloy::{
    primitives::{Address, ChainId},
    providers::Provider,
};
use metrics::gauge;

/// This collector queries a chain endpoint for balance of the signer.
pub struct BalanceCollector<P> {
    /// Address to be queried.
    address: Address,
    /// Chains endpoints.
    providers_with_chain: Vec<(ChainId, P)>,
}

impl<P> BalanceCollector<P> {
    pub fn new(address: Address, providers_with_chain: Vec<(ChainId, P)>) -> Self {
        Self { address, providers_with_chain }
    }
}

impl<P> MetricCollector for BalanceCollector<P>
where
    P: Provider,
{
    async fn collect(&self) -> Result<(), MetricCollectorError> {
        for (chain_id, provider) in &self.providers_with_chain {
            let balance = provider.get_balance(self.address).await?;

            gauge!(
                "balance",
                "address"  => self.address.to_checksum(Some(*chain_id)),
                "chain_id" => format!("{chain_id}")
            )
            .set::<f64>(balance.into());
        }
        Ok(())
    }
}

impl<P> Debug for BalanceCollector<P>
where
    P: Provider,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BalanceCollector").field("address", &self.address).finish()
    }
}
