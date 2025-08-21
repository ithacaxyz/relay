//! LayerZero diagnostics for testing endpoint connectivity and quote functionality.

use super::{ChainDiagnosticsResult, chain::ConnectedChains};
use crate::{
    chains::Chains,
    config::LayerZeroConfig,
    interop::settler::layerzero::{
        ULN_CONFIG_TYPE,
        contracts::{
            ILayerZeroEndpointV2::{
                self, getReceiveLibraryCall, getReceiveLibraryReturn, quoteCall,
            },
            ILayerZeroSettler::{self, peersCall},
            MessagingFee, MessagingParams, UlnConfig,
        },
    },
};
use alloy::{
    primitives::{Address, B256, ChainId},
    providers::{CallItem, DynProvider, Failure, Provider},
    sol_types::SolValue,
};
use eyre::Result;
use futures_util::future::try_join_all;
use std::sync::Arc;
use tracing::info;

/// Run LayerZero diagnostics.
///
/// Checks:
/// - Endpoint configuration: Validates endpoint addresses and IDs are properly configured
/// - Chain coverage: Ensures all relay chains have corresponding LayerZero configuration
/// - Settlement readiness: Verifies settler can send messages between all chain pairs
/// - ULN configuration: Validates Ultra Light Node settings for each chain pair
/// - DVN configuration: Checks Decentralized Verifier Network settings
///   - Ensures required DVN count matches actual DVN addresses
///   - Validates no zero addresses in DVN lists
///   - Confirms at least one DVN is configured (required or optional)
/// - Message fees: Confirms quote generation works for cross-chain messages
/// - Library configuration: Validates receive library is properly set for each endpoint
pub async fn run_layerzero_diagnostics(
    lz_config: &LayerZeroConfig,
    chains: Arc<Chains>,
    connected_chains: &ConnectedChains,
) -> Result<ChainDiagnosticsResult> {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    // Run checks for each connection pair
    let results = try_join_all(connected_chains.iter().map(|&(chain_a, chain_b)| {
        let chains = chains.clone();
        check_connection(lz_config, chains, chain_a, chain_b)
    }))
    .await?;

    for result in results {
        warnings.extend(result.warnings);
        errors.extend(result.errors);
    }

    Ok(ChainDiagnosticsResult { chain_id: 0, warnings, errors })
}

/// Check LayerZero configuration for a connection between two chains.
///
/// This validates the connection in both directions (A->B and B->A).
async fn check_connection(
    lz_config: &LayerZeroConfig,
    chains: Arc<Chains>,
    chain_a_id: ChainId,
    chain_b_id: ChainId,
) -> Result<ConnectionCheckResult> {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    info!("Checking LayerZero connection between chains {} and {}", chain_a_id, chain_b_id);

    // Check both directions of the connection
    for (src_chain_id, dst_chain_id) in [(chain_a_id, chain_b_id), (chain_b_id, chain_a_id)] {
        match check_connection_direction(lz_config, &chains, src_chain_id, dst_chain_id).await {
            Ok(result) => {
                warnings.extend(result.warnings);
                errors.extend(result.errors);
            }
            Err(e) => {
                errors.push(format!(
                    "Failed to check connection {src_chain_id} -> {dst_chain_id}: {e}"
                ));
            }
        }
    }

    Ok(ConnectionCheckResult { warnings, errors })
}

/// Check a single direction of a LayerZero connection.
async fn check_connection_direction(
    lz_config: &LayerZeroConfig,
    chains: &Arc<Chains>,
    src_chain_id: ChainId,
    dst_chain_id: ChainId,
) -> Result<ConnectionCheckResult> {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    // Validate source chain configuration
    let chain_config = match validate_chain_configs(lz_config, chains, src_chain_id, dst_chain_id) {
        Ok(config) => config,
        Err(e) => {
            errors.push(e);
            return Ok(ConnectionCheckResult { warnings, errors });
        }
    };

    // Get provider for source chain
    let Some(src_provider) = chains.get(src_chain_id).map(|chain| chain.provider().clone()) else {
        errors.push(format!("No provider available for chain {src_chain_id}"));
        return Ok(ConnectionCheckResult { warnings, errors });
    };

    info!(
        src_chain = %src_chain_id,
        dst_chain = %dst_chain_id,
        "Executing LayerZero diagnostics for connection direction"
    );

    // Create context for this connection direction
    let ctx = ConnectionContext {
        lz_config,
        src_provider: &src_provider,
        src_chain_id,
        dst_chain_id,
        dst_eid: chain_config.dst_eid,
        settler_address: chain_config.settler_address,
    };

    let results = ctx.execute_multicall_checks(chain_config.src_endpoint_address).await?;
    ctx.process_quote(&results.quote, &mut errors);
    ctx.process_library_and_config(&results.library, &mut warnings, &mut errors).await;
    ctx.process_peer(&results.peer, &mut errors);

    Ok(ConnectionCheckResult { warnings, errors })
}

/// Validate that both chains have required LayerZero configuration.
fn validate_chain_configs(
    lz_config: &LayerZeroConfig,
    chains: &Arc<Chains>,
    src_chain_id: ChainId,
    dst_chain_id: ChainId,
) -> Result<ChainConnectionConfig, String> {
    // Check source chain endpoint address
    let src_endpoint_address = lz_config.endpoint_addresses.get(&src_chain_id)
        .ok_or_else(|| format!(
            "Chain {src_chain_id} should be connected to chain {dst_chain_id} but has no LayerZero endpoint address configured"
        ))?;

    // Check source chain endpoint ID
    lz_config.endpoint_ids.get(&src_chain_id).ok_or_else(|| {
        format!(
            "Chain {src_chain_id} should be connected to chain {dst_chain_id} but has no LayerZero endpoint ID configured"
        )
    })?;

    // Check destination chain endpoint ID
    let dst_eid = lz_config.endpoint_ids.get(&dst_chain_id)
        .ok_or_else(|| format!(
            "Chain {src_chain_id} should be connected to chain {dst_chain_id} but chain {dst_chain_id} has no LayerZero endpoint ID configured"
        ))?;

    Ok(ChainConnectionConfig {
        src_endpoint_address: *src_endpoint_address,
        dst_eid: *dst_eid,
        settler_address: chains.settler_address(src_chain_id).map_err(|e| e.to_string())?,
    })
}

/// Helper struct to hold context for checking a connection direction.
struct ConnectionContext<'a> {
    lz_config: &'a LayerZeroConfig,
    src_provider: &'a DynProvider,
    src_chain_id: ChainId,
    dst_chain_id: ChainId,
    dst_eid: u32,
    settler_address: Address,
}

/// Result of checking a LayerZero connection.
struct ConnectionCheckResult {
    warnings: Vec<String>,
    errors: Vec<String>,
}

/// Result of multicall checks.
struct MulticallResults {
    quote: Result<MessagingFee, Failure>,
    library: Result<getReceiveLibraryReturn, Failure>,
    peer: Result<B256, Failure>,
}

/// Configuration data for a chain connection.
struct ChainConnectionConfig {
    src_endpoint_address: Address,
    dst_eid: u32,
    settler_address: Address,
}

impl<'a> ConnectionContext<'a> {
    /// Process quote result.
    fn process_quote(
        &self,
        quote_result: &Result<MessagingFee, Failure>,
        errors: &mut Vec<String>,
    ) {
        let Ok(fee) = quote_result else {
            errors.push(format!(
                "Quote failed for {} -> {}: {}",
                self.src_chain_id,
                self.dst_chain_id,
                quote_result.as_ref().unwrap_err()
            ));
            return;
        };

        info!(
            src_chain = %self.src_chain_id,
            dst_chain = %self.dst_chain_id,
            native_fee = %fee.nativeFee,
            "LayerZero quote successful"
        );
    }

    /// Process library result and fetch ULN configuration.
    async fn process_library_and_config(
        &self,
        lib_result: &Result<getReceiveLibraryReturn, Failure>,
        warnings: &mut Vec<String>,
        errors: &mut Vec<String>,
    ) {
        let Ok(lib_info) = lib_result else {
            errors.push(format!(
                "Get receive library failed for {} -> {}: {}",
                self.src_chain_id,
                self.dst_chain_id,
                lib_result.as_ref().unwrap_err()
            ));
            return;
        };

        info!(
            src_chain = %self.src_chain_id,
            dst_chain = %self.dst_chain_id,
            library = ?lib_info.lib,
            is_default = %lib_info.isDefault,
            "LayerZero receive library configured"
        );

        // Fetch and validate ULN configuration
        self.fetch_and_validate_uln_config(lib_info.lib, warnings, errors).await;
    }

    /// Fetch and validate ULN configuration.
    async fn fetch_and_validate_uln_config(
        &self,
        lib_address: Address,
        warnings: &mut Vec<String>,
        errors: &mut Vec<String>,
    ) {
        let endpoint = ILayerZeroEndpointV2::new(
            self.lz_config.endpoint_addresses[&self.src_chain_id],
            self.src_provider,
        );

        let Ok(config_bytes) = endpoint
            .getConfig(self.settler_address, lib_address, self.dst_eid, ULN_CONFIG_TYPE)
            .call()
            .await
        else {
            errors.push(format!(
                "Failed to fetch ULN config for {} -> {}",
                self.src_chain_id, self.dst_chain_id
            ));
            return;
        };

        let Ok(uln_config) = UlnConfig::abi_decode(&config_bytes) else {
            errors.push(format!(
                "Failed to decode ULN config for {} -> {}",
                self.src_chain_id, self.dst_chain_id
            ));
            return;
        };

        info!(
            src_chain = %self.src_chain_id,
            dst_chain = %self.dst_chain_id,
            uln_config = ?uln_config,
            "LayerZero ULN config retrieved"
        );
        self.validate_uln_config(&uln_config, warnings, errors);
    }

    /// Validate ULN configuration settings.
    fn validate_uln_config(
        &self,
        uln_config: &UlnConfig,
        warnings: &mut Vec<String>,
        errors: &mut Vec<String>,
    ) {
        // Validate confirmations
        if uln_config.confirmations == 0 {
            warnings.push(format!(
                "LayerZero ULN config has 0 confirmations for {} -> {}",
                self.src_chain_id, self.dst_chain_id
            ));
        }

        // Validate DVN configuration
        if uln_config.requiredDVNCount == 0 && uln_config.optionalDVNCount == 0 {
            errors.push(format!(
                "LayerZero ULN config has no DVNs configured for {} -> {}",
                self.src_chain_id, self.dst_chain_id
            ));
        }

        // Check DVN count consistency
        if uln_config.requiredDVNs.len() != uln_config.requiredDVNCount as usize {
            errors.push(format!(
                "LayerZero ULN config DVN count mismatch for {} -> {}: expected {} required DVNs but found {}",
                self.src_chain_id, self.dst_chain_id,
                uln_config.requiredDVNCount,
                uln_config.requiredDVNs.len()
            ));
        }

        // Check for zero addresses in DVNs
        for (i, dvn) in uln_config.requiredDVNs.iter().enumerate() {
            if dvn.is_zero() {
                errors.push(format!(
                    "LayerZero ULN config has zero address for required DVN {} for {} -> {}",
                    i, self.src_chain_id, self.dst_chain_id
                ));
            }
        }
    }

    /// Process peer result.
    fn process_peer(&self, peer_result: &Result<B256, Failure>, errors: &mut Vec<String>) {
        let expected_peer = B256::left_padding_from(self.settler_address.as_slice());

        let Ok(peer_bytes32) = peer_result else {
            errors.push(format!(
                "Get peer failed for {} -> {}: {}",
                self.src_chain_id,
                self.dst_chain_id,
                peer_result.as_ref().unwrap_err()
            ));
            return;
        };

        if *peer_bytes32 != expected_peer {
            errors.push(format!(
                "LayerZeroSettler@{} on chain {} has incorrect peer {} for chain {} (EID {}). Expected: {}",
                self.settler_address, self.src_chain_id, peer_bytes32,
                self.dst_chain_id, self.dst_eid, expected_peer
            ));
        } else {
            info!(
                src_chain = %self.src_chain_id,
                dst_chain = %self.dst_chain_id,
                dst_eid = %self.dst_eid,
                peer = %peer_bytes32,
                "LayerZeroSettler peer configured correctly"
            );
        }
    }

    /// Execute multicall checks for quote, library, and peer configuration.
    async fn execute_multicall_checks(
        &self,
        src_endpoint_address: Address,
    ) -> eyre::Result<MulticallResults> {
        let endpoint = ILayerZeroEndpointV2::new(src_endpoint_address, self.src_provider);
        let settler_contract = ILayerZeroSettler::new(self.settler_address, self.src_provider);
        let settlement_id = B256::random();

        let params = MessagingParams::new(
            self.src_chain_id,
            self.dst_eid,
            self.settler_address,
            settlement_id,
        );

        let (quote, library, peer) = self
            .src_provider
            .multicall()
            .add_call::<quoteCall>(
                CallItem::from(endpoint.quote(params, self.settler_address)).allow_failure(true),
            )
            .add_call::<getReceiveLibraryCall>(
                CallItem::from(endpoint.getReceiveLibrary(self.settler_address, self.dst_eid))
                    .allow_failure(true),
            )
            .add_call::<peersCall>(
                CallItem::from(settler_contract.peers(self.dst_eid)).allow_failure(true),
            )
            .aggregate3()
            .await?;

        Ok(MulticallResults { quote, library, peer })
    }
}
