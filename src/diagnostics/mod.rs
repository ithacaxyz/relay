//! Pre-flight diagnostics for relay startup.
//!
//! This module performs comprehensive validation of chain state before relay initialization,
//! ensuring all required contracts are deployed, funded, and properly configured.

mod chain;
mod layerzero;

use std::sync::Arc;

use chain::ConnectedChains;
pub use chain::{ChainDiagnostics, ChainDiagnosticsResult};

use crate::{
    chains::Chains,
    config::{RelayConfig, SettlerImplementation},
    signers::DynSigner,
};
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
                tracing::error!(chain_id = %chain_id, "Diagnostic error: {}", error);
            }
            for warning in &chain.warnings {
                warn!(chain_id = %chain_id, "Diagnostic warning: {}", warning);
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
pub async fn run_diagnostics(
    config: &RelayConfig,
    chains: Arc<Chains>,
    signers: &[DynSigner],
) -> Result<DiagnosticsReport> {
    let mut report = DiagnosticsReport {
        chains: Vec::new(),
        global_warnings: Vec::new(),
        global_errors: Vec::new(),
    };

    if chains.len() != config.chains.len() {
        report.global_errors.push(format!(
            "Provider count ({}) doesn't match endpoint count ({})",
            chains.len(),
            config.chains.len()
        ));
    }

    // Run chain diagnostics
    report.chains = try_join_all(chains.chains_iter().map(async |chain| {
        info!(chain_id = %chain.id(), "Running diagnostics");
        ChainDiagnostics::new(chain.clone(), config).run(signers).await
    }))
    .await?;

    if config.chains.len() > 1 && config.interop.is_none() {
        report.global_warnings.push(
            "No configuration for interop found, but more than one endpoint was configured."
                .to_string(),
        )
    }

    // Find out connected chains through their interop assets.
    let connected_chains = ConnectedChains::new(config);
    connected_chains.ensure_no_mainnet_testnet_connections(
        &mut report.global_errors,
        &mut report.global_warnings,
    );

    // Run LayerZero diagnostics if configured
    if let Some(interop) = &config.interop
        && let SettlerImplementation::LayerZero(lz_config) = &interop.settler.implementation
    {
        info!("Running LayerZero diagnostics");
        match layerzero::run_layerzero_diagnostics(lz_config, chains, &connected_chains).await {
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
