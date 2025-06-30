//! Common utilities for LayerZero testing
//!
//! This module provides shared utilities used across LayerZero tests,
//! including provider creation, address conversion, and message handling.

use super::relayer::{IEndpointV2Mock, IMessageLibManager};
use alloy::{
    network::Ethereum,
    primitives::{Address, B256, Bytes, U256, keccak256},
    providers::{Provider, ext::AnvilApi},
};
use eyre::Result;

/// Default executor address for LayerZero messages
pub const EXECUTOR_ADDRESS: Address = Address::new([3u8; 20]);

/// Default amount to fund accounts for gas (1 ETH)
pub fn default_fund_amount() -> U256 {
    U256::from(1_000_000_000_000_000_000u128)
}

/// Converts an address to a 32-byte representation
///
/// LayerZero uses 32-byte addresses, so we pad Ethereum addresses with zeros.
pub fn address_to_bytes32(addr: Address) -> B256 {
    B256::from_slice(&[&[0u8; 12], addr.as_slice()].concat())
}

/// Creates an origin struct for LayerZero messages
pub fn create_origin(src_eid: u32, sender: Address, nonce: u64) -> IEndpointV2Mock::Origin {
    IEndpointV2Mock::Origin { srcEid: src_eid, sender: address_to_bytes32(sender), nonce }
}

/// Computes the GUID for a LayerZero message
///
/// The GUID is a unique identifier for each cross-chain message.
pub fn compute_guid(
    nonce: u64,
    src_eid: u32,
    src_escrow: Address,
    dst_eid: u32,
    dst_escrow: Address,
) -> B256 {
    keccak256(
        [
            nonce.to_be_bytes().as_slice(),
            src_eid.to_be_bytes().as_slice(),
            src_escrow.as_slice(),
            dst_eid.to_be_bytes().as_slice(),
            dst_escrow.as_slice(),
        ]
        .concat(),
    )
}

/// Verifies a LayerZero message using the receive library
pub async fn verify_message<P: Provider + AnvilApi<Ethereum>>(
    provider: &P,
    dst_endpoint: Address,
    src_eid: u32,
    origin: &IEndpointV2Mock::Origin,
    dst_escrow: Address,
    payload_hash: B256,
) -> Result<()> {
    let lib_manager = IMessageLibManager::new(dst_endpoint, provider);
    let receive_lib = lib_manager.defaultReceiveLibrary(src_eid).call().await?;

    // Fund and impersonate the receive library
    provider.anvil_set_balance(receive_lib, default_fund_amount()).await?;
    provider.anvil_impersonate_account(receive_lib).await?;

    let endpoint = IEndpointV2Mock::new(dst_endpoint, provider);

    // Build the transaction request
    let tx_request = endpoint
        .verify(origin.clone(), dst_escrow, payload_hash)
        .from(receive_lib)
        .into_transaction_request();

    // Send as impersonated transaction
    let tx_hash = provider.anvil_send_impersonated_transaction(tx_request).await?;

    // Wait for the transaction to be mined
    provider.get_transaction_receipt(tx_hash).await?;
    provider.anvil_stop_impersonating_account(receive_lib).await?;
    Ok(())
}

/// Executes the lzReceive function on the endpoint
pub async fn execute_lz_receive<P: Provider + AnvilApi<Ethereum>>(
    provider: &P,
    dst_endpoint: Address,
    origin: &IEndpointV2Mock::Origin,
    dst_escrow: Address,
    guid: B256,
    message: Bytes,
) -> Result<()> {
    // Fund the executor
    provider.anvil_set_balance(EXECUTOR_ADDRESS, default_fund_amount()).await?;
    provider.anvil_impersonate_account(EXECUTOR_ADDRESS).await?;

    let endpoint = IEndpointV2Mock::new(dst_endpoint, provider);

    // Build the transaction request
    let tx_request = endpoint
        .lzReceive(origin.clone(), dst_escrow, guid, message, Bytes::new())
        .from(EXECUTOR_ADDRESS)
        .into_transaction_request();

    // Send as impersonated transaction
    let tx_hash = provider.anvil_send_impersonated_transaction(tx_request).await?;

    // Wait for the transaction to be mined
    provider.get_transaction_receipt(tx_hash).await?;
    provider.anvil_stop_impersonating_account(EXECUTOR_ADDRESS).await?;
    Ok(())
}
