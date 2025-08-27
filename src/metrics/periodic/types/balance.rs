use alloy::{primitives::U256, providers::Failure};
use itertools::Itertools;
use std::{fmt::Debug, sync::Arc};

use crate::{
    chains::{Chain, Chains},
    metrics::periodic::{MetricCollector, MetricCollectorError, types::format_units_f64},
    types::IERC20::{IERC20Instance, balanceOfCall},
};
use alloy::{
    primitives::Address,
    providers::{CallItem, MULTICALL3_ADDRESS, Provider, bindings::IMulticall3::getEthBalanceCall},
    sol_types::SolCall,
};
use futures_util::StreamExt;
use metrics::gauge;
use tracing::error;

enum BalancesFuture<S, F> {
    Signer(S),
    Funder(F),
}

/// This collector queries a chain endpoint for balance of the signers and funders per chain.
#[derive(Debug)]
pub struct BalanceCollector {
    /// Funder address.
    funder: Address,
    /// Chains.
    chains: Arc<Chains>,
}

impl BalanceCollector {
    /// Create a new balance collector.
    pub fn new(funder: Address, chains: Arc<Chains>) -> Self {
        Self { funder, chains }
    }
}

impl MetricCollector for BalanceCollector {
    async fn collect(&self) -> Result<(), MetricCollectorError> {
        // Prepare signer and funder balance multicalls
        let mut signer_requests = Vec::new();
        let mut funder_requests = Vec::new();
        for chain_ref in self.chains.chains_iter() {
            // Signer balances
            let chain = chain_ref.clone();
            signer_requests.push(BalancesFuture::Signer(Box::pin(async move {
                chain
                    .signer_addresses()
                    .fold(
                        chain.provider().multicall().dynamic::<getEthBalanceCall>(),
                        |multicall, signer| {
                            multicall.add_call_dynamic(CallItem::new(
                                MULTICALL3_ADDRESS,
                                getEthBalanceCall { addr: signer }.abi_encode().into(),
                            ))
                        },
                    )
                    .aggregate3()
                    .await
                    .map(|balances| (chain, balances))
            })));

            // Funder balances
            let chain = chain_ref.clone();
            let funder = self.funder;
            funder_requests.push(BalancesFuture::Funder(Box::pin(async move {
                let mut balances = chain
                    .assets()
                    .fee_token_iter_sorted()
                    // Filter out native token, we need to handle it separately
                    .filter(|(_, desc)| !desc.address.is_zero())
                    .fold(
                        chain.provider().multicall().dynamic::<balanceOfCall>(),
                        |multicall, (_, token)| {
                            let erc20 = IERC20Instance::new(token.address, chain.provider());
                            multicall.add_dynamic(erc20.balanceOf(funder))
                        },
                    )
                    .aggregate3()
                    .await
                    .map_err(eyre::Report::from)?;

                // Add native token balance at the position of native token in fee token list
                if let Some(native_balance_position) = chain
                    .assets()
                    .fee_token_iter_sorted()
                    .position(|(_, desc)| desc.address.is_zero())
                {
                    let native_balance =
                        chain.provider().get_balance(funder).await.map_err(eyre::Report::from)?;
                    balances.insert(native_balance_position, Ok(native_balance));
                } else {
                    error!(chain_id = ?chain.id(), "No native token found");
                }

                eyre::Ok((chain, balances))
            })));
        }

        // Interleave two sets of requests, so the order of chains alternates
        let requests = signer_requests.into_iter().interleave(funder_requests);

        // Process with bounded concurrency
        futures::stream::iter(requests)
            .map(|request| async move {
                match request {
                    BalancesFuture::Signer(fut) => {
                        let (chain, balances) = fut.await?;
                        record_signer_metrics(chain, balances);
                    }
                    BalancesFuture::Funder(fut) => {
                        let (chain, balances) = fut.await?;
                        record_funder_metrics(self.funder, chain, balances);
                    }
                }
                eyre::Ok(())
            })
            .buffered(self.chains.len())
            .for_each(|_| futures::future::ready(()))
            .await;

        Ok(())
    }
}

/// Records metrics for chain signers.
///
/// Once input balance corresponds to one singer.
fn record_signer_metrics(chain: Chain, balances: Vec<Result<U256, Failure>>) {
    let (symbol, decimals) = chain
        .native_symbol()
        .zip(chain.assets().native().map(|(_, a)| a.decimals))
        .unwrap_or(("ETH", 18));

    for (signer, balance) in chain.signer_addresses().zip(balances) {
        let balance = match balance {
            Ok(balance) => balance,
            Err(err) => {
                error!(chain_id = chain.id(), ?signer, ?err, "Failed to get signer balance");
                continue;
            }
        };

        match format_units_f64(balance, decimals) {
            Ok(balance) => gauge!(
                "signer.balance",
                "address" => signer.to_checksum(Some(chain.id())),
                "chain_id" => chain.id().to_string(),
                "symbol" => symbol.to_string(),
            )
            .set::<f64>(balance),
            Err(err) => {
                error!(?balance, ?decimals, ?err, "Failed to format signer balance")
            }
        }
    }
}

/// Records metrics for chain funder, per fee token.
///
/// Once input balance corresponds to one fee token.
fn record_funder_metrics(funder: Address, chain: Chain, balances: Vec<Result<U256, Failure>>) {
    for ((uid, token), balance) in chain.assets().fee_token_iter_sorted().zip(balances) {
        let balance = match balance {
            Ok(balance) => balance,
            Err(err) => {
                error!(
                    chain_id = chain.id(),
                    token = ?token.address,
                    ?err,
                    "Failed to get funder balance"
                );
                continue;
            }
        };

        match format_units_f64(balance, token.decimals) {
            Ok(balance) => gauge!(
                "funder.balance",
                "address" => funder.to_checksum(Some(chain.id())),
                "chain_id" => chain.id().to_string(),
                "uid" => uid.to_string(),
            )
            .set::<f64>(balance),
            Err(err) => {
                error!(?balance, ?token, ?err, "Failed to format funder balance")
            }
        }
    }
}
