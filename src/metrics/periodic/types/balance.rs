use crate::metrics::periodic::{MetricCollector, MetricCollectorError};
use alloy::{
    primitives::Address,
    providers::{Provider, ProviderBuilder},
    rpc::client::RpcClient,
};
use metrics::gauge;
use url::Url;

/// This collector queries a chain endpoint for balance of the signer.
#[derive(Debug)]
pub struct BalanceCollector {
    /// Address to be queried.
    pub address: Address,
    /// Chains endpoints.
    pub endpoints: Vec<Url>,
}

impl MetricCollector for BalanceCollector {
    async fn collect(&self) -> Result<(), MetricCollectorError> {
        for endpoint in &self.endpoints {
            let provider = ProviderBuilder::new()
                .with_recommended_fillers()
                .on_client(RpcClient::new_http(endpoint.clone()).boxed());

            let (chain_id, balance) =
                tokio::join!(provider.get_chain_id(), provider.get_balance(self.address));
            let chain_id = chain_id?;

            gauge!(
                "balance",
                "address"  => self.address.to_checksum(Some(chain_id)),
                "chain_id" => format!("{chain_id}")
            )
            .set::<f64>(balance?.into());
        }
        Ok(())
    }
}
