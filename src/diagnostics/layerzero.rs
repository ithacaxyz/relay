//! LayerZero diagnostics for testing endpoint connectivity and quote functionality.

use super::ChainDiagnosticsResult;
use crate::{
    config::{LayerZeroConfig, RelayConfig},
    interop::settler::layerzero::{
        ULN_CONFIG_TYPE,
        contracts::{
            ILayerZeroEndpointV2::{self, getConfigCall, getReceiveLibraryCall, quoteCall},
            ILayerZeroSettler::{self, peersCall},
            MessagingParams, UlnConfig,
        },
    },
};
use alloy::{
    primitives::{B256, Bytes, ChainId},
    providers::{CallItem, Provider},
    sol_types::SolValue,
};
use eyre::Result;
use futures_util::future::try_join_all;
use std::{collections::HashMap, sync::Arc};
use tokio::try_join;
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
pub async fn run_layerzero_diagnostics<P: Provider + Clone>(
    lz_config: &LayerZeroConfig,
    relay_config: &RelayConfig,
    providers: &[P],
    chain_ids: &[ChainId],
) -> Result<ChainDiagnosticsResult> {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    let mut provider_map = HashMap::new();
    for (provider, chain_id) in providers.iter().zip(chain_ids) {
        provider_map.insert(*chain_id, provider.clone());
    }

    // check that we have providers for all configured chains
    for chain_id in lz_config.endpoint_ids.keys() {
        if !provider_map.contains_key(chain_id) {
            errors
                .push(format!("LayerZero: No provider available for configured chain {chain_id}"));
        }
    }

    // Run checks for each chain
    let provider_map = Arc::new(provider_map);
    let results = try_join_all(lz_config.endpoint_ids.keys().map(|src_chain_id| {
        let provider_map = provider_map.clone();
        check_chain(lz_config, relay_config, provider_map, *src_chain_id)
    }))
    .await?;

    for (w, e) in results {
        warnings.extend(w);
        errors.extend(e);
    }

    Ok(ChainDiagnosticsResult { chain_id: 0, warnings, errors })
}

/// Run all LayerZero diagnostics for a single source chain.
async fn check_chain<P: Provider>(
    lz_config: &LayerZeroConfig,
    relay_config: &RelayConfig,
    providers: Arc<HashMap<ChainId, P>>,
    src_chain_id: ChainId,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    // Ensure there is an endpoint address for this chain
    let Some(src_endpoint_address) = lz_config.endpoint_addresses.get(&src_chain_id) else {
        errors.push(format!("No LayerZero endpoint configured for chain {src_chain_id}"));
        return Ok((warnings, errors));
    };

    // Ensure there is an endpoint id for this chain
    let Some(_local_eid) = lz_config.endpoint_ids.get(&src_chain_id) else {
        errors.push(format!("No LayerZero endpoint ID configured for chain {src_chain_id}"));
        return Ok((warnings, errors));
    };

    let Some(src_provider) = providers.get(&src_chain_id) else {
        errors.push(format!("No provider available for source chain {src_chain_id}"));
        return Ok((warnings, errors));
    };

    let endpoint = ILayerZeroEndpointV2::new(*src_endpoint_address, src_provider);

    // Prepare multicalls
    let mut multicall_quotes = src_provider.multicall().dynamic::<quoteCall>();
    let mut multicall_get_lib = src_provider.multicall().dynamic::<getReceiveLibraryCall>();
    let mut multicall_peers = src_provider.multicall().dynamic::<peersCall>();

    let settler_contract = ILayerZeroSettler::new(lz_config.settler_address, src_provider);
    let mut quote_dst_chains = Vec::new();
    let mut config_remote_chains = Vec::new();
    let mut peer_eids = Vec::new();
    let settlement_id = B256::random();

    // Build multicalls for each destination chain
    for (dst_chain_id, dst_endpoint_id) in &lz_config.endpoint_ids {
        // Skip self
        if *dst_chain_id == src_chain_id {
            continue;
        }

        // Create messaging params similar to the settler implementation
        let params = MessagingParams::new(
            src_chain_id,
            *dst_endpoint_id,
            lz_config.settler_address,
            settlement_id,
        );

        // Add quote call
        multicall_quotes = multicall_quotes.add_call_dynamic(
            CallItem::from(endpoint.quote(params, lz_config.settler_address)).allow_failure(true),
        );
        quote_dst_chains.push(*dst_chain_id);

        // Add getReceiveLibrary call
        multicall_get_lib = multicall_get_lib.add_call_dynamic(
            CallItem::from(endpoint.getReceiveLibrary(lz_config.settler_address, *dst_endpoint_id))
                .allow_failure(true),
        );
        config_remote_chains.push((*dst_chain_id, *dst_endpoint_id));

        // Add peers call
        multicall_peers = multicall_peers.add_call_dynamic(
            CallItem::from(settler_contract.peers(*dst_endpoint_id)).allow_failure(true),
        );
        peer_eids.push((*dst_chain_id, *dst_endpoint_id));
    }

    // Validate we have the expected number of remote chains
    let expected_remote_chains = relay_config.chain.endpoints.len() - 1;
    if config_remote_chains.len() != expected_remote_chains {
        errors.push(format!(
            "LayerZeroSettler@{} on chain {} only has {} chains configured instead of {}.",
            lz_config.settler_address,
            src_chain_id,
            config_remote_chains.len(),
            expected_remote_chains
        ));
    }

    // Execute all multicalls
    info!(chain_id = %src_chain_id, "Executing LZ multicalls: quotes, libs, peers");
    let (quote_results, lib_results, peer_results) = try_join!(
        multicall_quotes.aggregate3(),
        multicall_get_lib.aggregate3(),
        multicall_peers.aggregate3()
    )?;

    // Process quote results
    let chain_pairs: Vec<_> = quote_dst_chains.into_iter().map(|dst| (src_chain_id, dst)).collect();
    crate::process_multicall_results!(
        errors,
        quote_results,
        chain_pairs,
        |fee: crate::interop::settler::layerzero::contracts::MessagingFee, (src, dst)| {
            info!(
                src_chain_id = %src,
                dst_chain_id = %dst,
                native_fee = %fee.nativeFee,
                "LayerZero quote successful"
            );
        }
    );

    // Process library results and
    let mut valid_remote_chains = Vec::with_capacity(config_remote_chains.len());
    crate::process_multicall_results!(
        errors,
        lib_results,
        config_remote_chains.clone(),
        |lib_info: ILayerZeroEndpointV2::getReceiveLibraryReturn, (remote_chain_id, remote_eid)| {
            valid_remote_chains.push((lib_info.lib, (remote_chain_id, remote_eid)));
        }
    );

    // Build multicall_get_config to fetch ULN configurations for all valid remote chains
    let mut multicall_get_config = src_provider.multicall().dynamic::<getConfigCall>();
    for (lib, (_, remote_eid)) in &valid_remote_chains {
        multicall_get_config = multicall_get_config.add_call_dynamic(
            CallItem::from(endpoint.getConfig(
                lz_config.settler_address,
                *lib,
                *remote_eid,
                ULN_CONFIG_TYPE,
            ))
            .allow_failure(true),
        );
    }

    info!(
        chain_id = %src_chain_id,
        remote_chains = valid_remote_chains.len(),
        "Fetching ULN configs"
    );
    crate::process_multicall_results!(
        errors,
        multicall_get_config.aggregate3().await?,
        valid_remote_chains,
        |config_bytes: Bytes, (_, (remote_chain_id, remote_eid))| {
            // Decode and validate the ULN configuration
            let Ok(uln_config) = UlnConfig::abi_decode(&config_bytes) else {
                errors.push(format!(
                    "Failed to decode LayerZero ULN configuration for remote chain {remote_chain_id} (EID {remote_eid})"
                ));
                return;
            };

            // Log the ULN configuration
            info!(
                src_chain_id = %src_chain_id,
                remote_chain_id = %remote_chain_id,
                remote_eid = %remote_eid,
                uln_config = ?uln_config,
                "LayerZero ULN config retrieved"
            );

            // Validate confirmations
            if uln_config.confirmations == 0 {
                warnings.push(format!(
                    "LayerZero ULN config has 0 confirmations for remote chain {remote_chain_id} (EID {remote_eid})"
                ));
            }

            // Validate DVN configuration
            if uln_config.requiredDVNCount == 0 && uln_config.optionalDVNCount == 0 {
                errors.push(format!(
                    "LayerZero ULN config has no DVNs configured for remote chain {remote_chain_id} (EID {remote_eid})"
                ));
            }

            // Check DVN count consistency
            if uln_config.requiredDVNs.len() != uln_config.requiredDVNCount as usize {
                errors.push(format!(
                    "LayerZero ULN config DVN count mismatch: expected {} required DVNs but found {} for remote chain {} (EID {})",
                    uln_config.requiredDVNCount,
                    uln_config.requiredDVNs.len(),
                    remote_chain_id,
                    remote_eid
                ));
            }

            // Check for zero addresses in DVNs
            for (i, dvn) in uln_config.requiredDVNs.iter().enumerate() {
                if dvn.is_zero() {
                    errors.push(format!(
                        "LayerZero ULN config has zero address for required DVN {i} for remote chain {remote_chain_id} (EID {remote_eid})"
                    ));
                }
            }
        }
    );

    // Process peer results
    crate::process_multicall_results!(errors, peer_results, peer_eids, |peer_bytes32: B256,
                                                                        (
        dst_chain_id,
        dst_eid,
    )| {
        if peer_bytes32.is_zero() {
            errors.push(format!(
                "LayerZeroSettler@{} on chain {} has zero address peer for chain {} (EID {})",
                lz_config.settler_address, src_chain_id, dst_chain_id, dst_eid
            ));
        } else {
            info!(
                src_chain_id = %src_chain_id,
                dst_chain_id = %dst_chain_id,
                dst_eid = %dst_eid,
                peer = %peer_bytes32,
                "LayerZeroSettler peer configured"
            );
        }
    });

    Ok((warnings, errors))
}
