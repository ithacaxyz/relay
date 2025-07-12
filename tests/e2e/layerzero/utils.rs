//! Common utilities for LayerZero testing
//!
//! This module provides shared utilities used across LayerZero tests,
//! including provider creation, address conversion, and message handling.

use super::interfaces::IMessageLibManager;
use crate::e2e::send_impersonated_tx;
use alloy::{
    network::Ethereum,
    primitives::{Address, B256, Bytes, U256, keccak256},
    providers::{Provider, ext::AnvilApi},
    uint,
};
use eyre::Result;
use relay::interop::settler::layerzero::contracts::{ILayerZeroEndpointV2, Origin};

/// Default executor address for LayerZero messages
pub const EXECUTOR_ADDRESS: Address = Address::new([3u8; 20]);

/// Default amount to fund accounts for gas (1 ETH)
const DEFAULT_FUND_AMOUNT: U256 = uint!(1_000_000_000_000_000_000_U256);

/// Converts an address to a 32-byte representation
///
/// LayerZero uses 32-byte addresses, so we pad Ethereum addresses with zeros.
pub fn address_to_bytes32(addr: Address) -> B256 {
    B256::from_slice(&[&[0u8; 12], addr.as_slice()].concat())
}

/// Extracts an address from a 32-byte representation
///
/// LayerZero uses 32-byte addresses, this extracts the last 20 bytes as an Ethereum address.
pub fn bytes32_to_address(bytes32: &B256) -> Address {
    Address::from_slice(&bytes32[12..])
}

/// Creates an origin struct for LayerZero messages
pub fn create_origin(src_eid: u32, sender: Address, nonce: u64) -> Origin {
    Origin { srcEid: src_eid, sender: address_to_bytes32(sender), nonce }
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
    origin: &Origin,
    dst_escrow: Address,
    payload_hash: B256,
) -> Result<()> {
    let receive_lib = IMessageLibManager::new(dst_endpoint, provider)
        .defaultReceiveLibrary(src_eid)
        .call()
        .await?;

    send_impersonated_tx(
        provider,
        ILayerZeroEndpointV2::new(dst_endpoint, provider)
            .verify(origin.clone(), dst_escrow, payload_hash)
            .from(receive_lib)
            .into_transaction_request(),
        Some(DEFAULT_FUND_AMOUNT),
    )
    .await
}

/// Executes the lzReceive function on the endpoint
pub async fn execute_lz_receive<P: Provider + AnvilApi<Ethereum>>(
    provider: &P,
    dst_endpoint: Address,
    origin: &Origin,
    dst_escrow: Address,
    guid: B256,
    message: Bytes,
) -> Result<()> {
    send_impersonated_tx(
        provider,
        ILayerZeroEndpointV2::new(dst_endpoint, provider)
            .lzReceive(origin.clone(), dst_escrow, guid, message, Bytes::new())
            .from(EXECUTOR_ADDRESS)
            .into_transaction_request(),
        Some(DEFAULT_FUND_AMOUNT),
    )
    .await
}

/// Delivers a LayerZero message from source to destination
///
/// This is the core message delivery function that:
/// 1. Prepares the message payload
/// 2. Verifies the message on destination
/// 3. Executes the lzReceive function (only for escrow contracts)
#[expect(clippy::too_many_arguments)]
pub async fn deliver_layerzero_message<P: Provider + AnvilApi<Ethereum>>(
    provider: &P,
    dst_endpoint: Address,
    src_eid: u32,
    origin: &Origin,
    receiver: Address,
    guid: B256,
    message: Bytes,
    escrows: &[Address],
) -> Result<()> {
    // Prepare payload and hash
    let payload = [guid.as_slice(), message.as_ref()].concat();
    let payload_hash = keccak256(&payload);

    // Verify the message
    verify_message(provider, dst_endpoint, src_eid, origin, receiver, payload_hash).await?;

    // Only execute lzReceive if the receiver is an escrow contract
    // This is necessary because only escrow contracts implement the lzReceive interface
    // in our test setup.
    if escrows.contains(&receiver) {
        execute_lz_receive(provider, dst_endpoint, origin, receiver, guid, message).await?;
    }

    Ok(())
}
