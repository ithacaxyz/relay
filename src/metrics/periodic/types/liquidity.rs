use std::{fmt::Debug, sync::Arc};

use alloy::primitives::U256;
use futures::future::try_join;
use itertools::Itertools;
use metrics::gauge;
use tracing::error;

use crate::{
    chains::Chains,
    metrics::periodic::{MetricCollector, MetricCollectorError, types::format_units_f64},
    storage::{RelayStorage, StorageApi},
};

/// This collector queries a chain endpoint for balance of the signers per chain.
#[derive(Debug)]
pub struct LiquidityCollector {
    /// Storage.
    storage: RelayStorage,
    /// Chains.
    chains: Arc<Chains>,
}

impl LiquidityCollector {
    /// Create a new liquidity collector.
    pub fn new(storage: RelayStorage, chains: Arc<Chains>) -> Self {
        Self { storage, chains }
    }
}

impl MetricCollector for LiquidityCollector {
    async fn collect(&self) -> Result<(), MetricCollectorError> {
        let (locked, pending) = try_join(
            self.storage.get_total_locked_liquidity(),
            self.storage.get_total_pending_unlocks(),
        )
        .await?;

        for chain_address @ (chain_id, address) in locked.keys().chain(pending.keys()).unique() {
            let Some(chain) = self.chains.get(*chain_id) else {
                error!(?chain_id, "Unknown chain ID");
                continue;
            };

            let Some((uid, asset)) = chain.assets().find_by_address(*address) else {
                error!(?address, "Unknown asset address");
                continue;
            };

            let decimals = asset.decimals;

            if let Some((locked_liquidity, pending_unlock)) =
                locked.get(chain_address).zip(pending.get(chain_address).or(Some(&U256::ZERO)))
            {
                let locked_liquidity = format_units_f64(*locked_liquidity, decimals);
                let pending_unlock = format_units_f64(*pending_unlock, decimals);

                if let Some((locked_liquidity, pending_unlock)) =
                    locked_liquidity.ok().zip(pending_unlock.ok())
                {
                    gauge!(
                        "liquidity.locked",
                        "chain_id" => chain_id.to_string(),
                        "address" => address.to_string(),
                        "uid" => uid.to_string(),
                    )
                    .set::<f64>(locked_liquidity - pending_unlock);

                    gauge!(
                        "liquidity.pending_unlock",
                        "chain_id" => chain_id.to_string(),
                        "address" => address.to_string(),
                        "uid" => uid.to_string(),
                    )
                    .set::<f64>(pending_unlock);
                }
            }
        }

        Ok(())
    }
}
