//! Common utilities for LayerZero testing
//!
//! This module provides shared utilities used across LayerZero tests,
//! including provider creation, address conversion, and message handling.

use super::interfaces::{IMessageLibManager, IReceiveUlnE2, SetConfigParam as ISetConfigParam};
use crate::e2e::{layerzero::interfaces::UlnConfig, send_impersonated_tx};
use alloy::{
    network::Ethereum,
    primitives::{Address, B256, Bytes, U256, keccak256},
    providers::{Provider, ext::AnvilApi},
    sol_types::SolValue,
    uint,
};
use eyre::Result;
use futures_util::future::try_join_all;
use relay::interop::settler::layerzero::{
    ULN_CONFIG_TYPE,
    contracts::{ILayerZeroEndpointV2, Origin},
};

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

/// Creates a packet header for LayerZero V2 messages
fn create_packet_header(
    nonce: u64,
    src_eid: u32,
    sender: Address,
    dst_eid: u32,
    receiver: Address,
) -> Bytes {
    // PacketV1Codec format: version (1 byte) + nonce (8) + srcEid (4) + sender (32) + dstEid (4) +
    // receiver (32)
    let mut header = Vec::with_capacity(81);
    header.push(1u8); // version
    header.extend_from_slice(&nonce.to_be_bytes());
    header.extend_from_slice(&src_eid.to_be_bytes());
    header.extend_from_slice(&address_to_bytes32(sender).0);
    header.extend_from_slice(&dst_eid.to_be_bytes());
    header.extend_from_slice(&address_to_bytes32(receiver).0);
    Bytes::from(header)
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

/// Configures ULN settings for a specific endpoint and OApp
pub async fn configure_uln_for_endpoint<P: Provider + AnvilApi<Ethereum>>(
    provider: &P,
    endpoint: Address,
    oapps: &[Address],
    send_lib: Address,
    remote_eid: u32,
    dvn_address: Address,
) -> Result<()> {
    // Create ULN config with 1 confirmation and 1 required DVN
    let uln_config = UlnConfig {
        confirmations: 1,
        requiredDVNCount: 1,
        optionalDVNCount: 0,
        optionalDVNThreshold: 0,
        requiredDVNs: vec![dvn_address],
        optionalDVNs: vec![],
    };

    // Encode ULN config
    let encoded_uln = uln_config.abi_encode();

    // Create SetConfigParam for ULN only
    let params = vec![ISetConfigParam {
        eid: remote_eid,
        configType: ULN_CONFIG_TYPE,
        config: encoded_uln.into(),
    }];

    // Set config via MessageLibManager (the endpoint acts as MessageLibManager)
    try_join_all(oapps.iter().map(async |oapp| {
        IMessageLibManager::new(endpoint, provider)
            .setConfig(*oapp, send_lib, params.clone())
            .send()
            .await
            .unwrap()
            .get_receipt()
            .await
    }))
    .await?;

    Ok(())
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
/// This is the core message delivery function that implements the correct LayerZero V2 flow:
/// 1. Prepares the message payload and packet header
/// 2. DVN verifies the message by calling ULN._verify
/// 3. Executor commits verification by calling ULN.commitVerification
/// 4. Executor executes the lzReceive function (only for escrow contracts)
#[expect(clippy::too_many_arguments)]
pub async fn deliver_layerzero_message<P: Provider + AnvilApi<Ethereum>>(
    provider: &P,
    dst_endpoint: Address,
    src_eid: u32,
    dst_eid: u32,
    origin: &Origin,
    receiver: Address,
    guid: B256,
    message: Bytes,
    escrows: &[Address],
) -> Result<()> {
    // Prepare payload and hash
    let payload = [guid.as_slice(), message.as_ref()].concat();
    let payload_hash = keccak256(&payload);

    // Get the ULN (receive library) address for this source chain
    let uln_address = IMessageLibManager::new(dst_endpoint, provider)
        .defaultReceiveLibrary(src_eid)
        .call()
        .await?;

    // Create packet header for verification
    let sender = bytes32_to_address(&origin.sender);
    let packet_header = create_packet_header(origin.nonce, src_eid, sender, dst_eid, receiver);

    // dvn verify
    send_impersonated_tx(
        provider,
        IReceiveUlnE2::new(uln_address, provider)
            .verify(packet_header.clone(), payload_hash, 1)
            .from(EXECUTOR_ADDRESS)
            .into_transaction_request(),
        Some(DEFAULT_FUND_AMOUNT),
    )
    .await?;

    // This is necessary because only escrow contracts implement the lzReceive interface
    // in our test setup.
    //
    // In non relay test cases (MockEscrow), we need the testing suite to execute lzReceive to
    // ensure that the layerzero setup is working. In normal relay operations, the settlement
    // system will be the one acting as the executor.
    if escrows.contains(&receiver) {
        // executor commits the verification (once it has reached the dvn threshold)
        send_impersonated_tx(
            provider,
            IReceiveUlnE2::new(uln_address, provider)
                .commitVerification(packet_header.clone(), payload_hash)
                .from(EXECUTOR_ADDRESS)
                .into_transaction_request(),
            Some(DEFAULT_FUND_AMOUNT),
        )
        .await?;

        execute_lz_receive(provider, dst_endpoint, origin, receiver, guid, message).await?;
    }

    Ok(())
}
