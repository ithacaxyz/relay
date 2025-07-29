//! Pre-flight diagnostics for relay startup.
//!
//! This module performs comprehensive validation of chain state before relay initialization,
//! ensuring all required contracts are deployed, funded, and properly configured.

mod chain;
mod layerzero;

pub use chain::{ChainDiagnostics, ChainDiagnosticsResult};

use crate::{
    config::{RelayConfig, SettlerImplementation},
    signers::DynSigner,
    types::FeeTokens,
};
use alloy::providers::Provider;
use eyre::Result;
use futures_util::future::try_join_all;
use tracing::{info, warn};

/// Aggregated diagnostic results
#[derive(Debug)]
pub struct DiagnosticsReport {
    /// Diagnostics for each chain
    pub chains: Vec<ChainDiagnosticsResult>,
    /// Global warning messages
    pub global_warnings: Vec<String>,
    /// Global error messages  
    pub global_errors: Vec<String>,
}

impl DiagnosticsReport {
    /// Returns true if there are any errors
    pub fn has_errors(&self) -> bool {
        !self.global_errors.is_empty() || self.chains.iter().any(|c| !c.errors.is_empty())
    }

    /// Returns true if there are any warnings
    pub fn has_warnings(&self) -> bool {
        !self.global_warnings.is_empty() || self.chains.iter().any(|c| !c.warnings.is_empty())
    }

    /// Logs all messages.
    pub fn log(&self) {
        for error in &self.global_errors {
            tracing::error!("Global diagnostic error: {}", error);
        }
        for warning in &self.global_warnings {
            warn!("Global diagnostic warning: {}", warning);
        }

        // Log per-chain issues
        for chain in &self.chains {
            let chain_id = chain.chain_id;
            for error in &chain.errors {
                tracing::error!("Chain {} diagnostic error: {}", chain_id, error);
            }
            for warning in &chain.warnings {
                warn!("Chain {} diagnostic warning: {}", chain_id, warning);
            }
        }

        if self.has_errors() {
            tracing::error!("Diagnostics failed with errors. Relay startup may fail.");
        } else if self.has_warnings() {
            warn!("Diagnostics completed with warnings. Relay may not function optimally.");
        } else {
            info!("All diagnostics passed successfully.");
        }
    }
}

/// Runs diagnostics on the relay configuration
pub async fn run_diagnostics<P: Provider + Clone>(
    config: &RelayConfig,
    providers: &[P],
    signers: &[DynSigner],
    fee_tokens: &FeeTokens,
) -> Result<DiagnosticsReport> {
    let mut report = DiagnosticsReport {
        chains: Vec::new(),
        global_warnings: Vec::new(),
        global_errors: Vec::new(),
    };

    if providers.len() != config.chain.endpoints.len() {
        report.global_errors.push(format!(
            "Provider count ({}) doesn't match endpoint count ({})",
            providers.len(),
            config.chain.endpoints.len()
        ));
    }

    let chain_ids: Vec<_> =
        try_join_all(providers.iter().map(async |provider| provider.get_chain_id().await)).await?;

    // Run chain diagnostics
    report.chains =
        try_join_all(providers.iter().zip(&chain_ids).map(async |(provider, chain_id)| {
            info!("Running diagnostics for chain {}", chain_id);
            ChainDiagnostics::new(provider.clone(), *chain_id, config)
                .run(fee_tokens, signers)
                .await
        }))
        .await?;

    if config.chain.endpoints.len() > 1 && config.interop.is_none() {
        report.global_errors.push(
            "No configuration for interop found, but more than one endpoint was configured."
                .to_string(),
        )
    }

    // Run LayerZero diagnostics if configured
    if let Some(interop) = &config.interop
        && let SettlerImplementation::LayerZero(lz_config) = &interop.settler.implementation
    {
        match layerzero::run_layerzero_diagnostics(lz_config, config, providers, &chain_ids).await {
            Ok(lz_result) => {
                report.global_warnings.extend(lz_result.warnings);
                report.global_errors.extend(lz_result.errors);
            }
            Err(e) => {
                report.global_errors.push(format!("LayerZero diagnostics failed: {e}"));
            }
        }
    }

    Ok(report)
}

/// Helper macro to process multicall results.
#[macro_export]
macro_rules! process_multicall_results {
    ($errors:expr, $results:expr, $items:expr, $on_success:expr) => {
        assert!(
            $results.len() == $items.len(),
            "multicall result should have returned the same number of elements"
        );
        for (result, (name, address)) in $results.into_iter().zip($items) {
            match result {
                Ok(value) => $on_success(value, (name, address)),
                Err(err) => {
                    $errors.push(format!("error on calling {name}@{address:?}: {err}"));
                }
            }
        }
    };
}
