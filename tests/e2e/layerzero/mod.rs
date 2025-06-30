//! LayerZero cross-chain messaging test utilities
//!
//! This module provides utilities for testing LayerZero cross-chain communication,
//! including escrow contracts and message relaying functionality.

pub mod escrow;
pub mod relayer;
pub mod setup;
pub mod utils;

pub use setup::{LayerZeroConfig, LayerZeroEnvironment, create_providers_for_escrow_wiring};
pub use utils::address_to_bytes32;

use alloy::{
    primitives::{Address, Bytes, U256},
    providers::{Provider, WalletProvider},
    sol,
};
use eyre::Result;

sol! {
    /// LayerZero Escrow V2 contract interface
    ///
    /// This interface defines the escrow contract that locks tokens on one chain
    /// and releases them on another chain via LayerZero messaging.
    #[sol(rpc)]
    interface IMockEscrow {
        struct MessagingFee {
            uint256 nativeFee;
            uint256 lzTokenFee;
        }

        function setPeer(uint32 eid, bytes32 peer) external;
        function lockTokens(
            address token,
            uint256 amount,
            uint32 dstEid,
            address recipient,
            bytes calldata options
        ) external payable;
        function quoteLayerZeroFee(
            uint32 dstEid,
            address token,
            uint256 amount,
            address recipient,
            bytes calldata options
        ) external view returns (MessagingFee memory fee);
        function lockedBalances(address token, address user) external view returns (uint256);
    }
}

/// Builder for LayerZero message options
///
/// This builder creates LayerZero V3 options that configure how messages
/// are executed on the destination chain, including gas limits and native
/// token drops.
pub struct OptionsBuilder {
    options: Vec<u8>,
}

impl OptionsBuilder {
    /// Creates a new options builder with LayerZero V3 format
    ///
    /// The options start with a 2-byte header: 0x0003 for version 3
    pub fn new() -> Self {
        Self {
            options: vec![0x00, 0x03], // Version 3
        }
    }

    /// Adds executor lzReceive option with gas and native drop amount
    ///
    /// # Arguments
    /// * `gas` - Gas limit for the lzReceive execution on destination
    /// * `native_drop` - Amount of native tokens to send to the receiver
    pub fn add_executor_lz_receive_option(mut self, gas: u128, native_drop: u128) -> Self {
        const OPTION_TYPE_EXECUTOR: u8 = 0x01;
        const OPTION_LENGTH: u8 = 32; // 16 bytes gas + 16 bytes native drop

        self.options.push(OPTION_TYPE_EXECUTOR);
        self.options.push(OPTION_LENGTH);
        self.options.extend_from_slice(&gas.to_be_bytes());
        self.options.extend_from_slice(&native_drop.to_be_bytes());

        self
    }

    /// Builds the options into a Bytes object
    pub fn build(self) -> Bytes {
        self.options.into()
    }
}

/// Wires LayerZero escrows by setting peer relationships
///
/// This function establishes bidirectional trust between two escrow contracts
/// on different chains by setting their peer relationships. Each escrow will
/// only accept messages from its configured peer.
///
/// # Arguments
/// * `provider1` - Provider for chain 1 with wallet capabilities
/// * `provider2` - Provider for chain 2 with wallet capabilities
/// * `escrow1` - Address of escrow contract on chain 1
/// * `escrow2` - Address of escrow contract on chain 2
/// * `eid1` - Endpoint ID of chain 1
/// * `eid2` - Endpoint ID of chain 2
pub async fn wire_escrows<P1: Provider + WalletProvider, P2: Provider + WalletProvider>(
    provider1: &P1,
    provider2: &P2,
    escrow1: Address,
    escrow2: Address,
    eid1: u32,
    eid2: u32,
) -> Result<()> {
    let esc1 = IMockEscrow::new(escrow1, provider1);
    let esc2 = IMockEscrow::new(escrow2, provider2);

    // Create peer addresses (32-byte padded)
    let peer1 = address_to_bytes32(escrow1);
    let peer2 = address_to_bytes32(escrow2);

    // Set peers bidirectionally
    esc1.setPeer(eid2, peer2).send().await?.watch().await?;
    esc2.setPeer(eid1, peer1).send().await?.watch().await?;

    Ok(())
}

/// Quotes the LayerZero fee for a cross-chain transfer
///
/// This function queries the escrow contract to determine the required fee
/// for sending a cross-chain message. The fee covers gas costs on the
/// destination chain and LayerZero protocol fees.
///
/// # Arguments
/// * `provider` - Provider to interact with the escrow contract
/// * `escrow` - Address of the escrow contract
/// * `dst_eid` - Destination chain endpoint ID
/// * `token` - Token to be transferred
/// * `amount` - Amount of tokens to transfer
/// * `recipient` - Recipient address on destination chain
/// * `options` - LayerZero message options (gas limits, etc.)
///
/// # Returns
/// The native token fee required to send the message
pub async fn quote_layerzero_fee<P: Provider>(
    provider: &P,
    escrow: Address,
    dst_eid: u32,
    token: Address,
    amount: U256,
    recipient: Address,
    options: Bytes,
) -> Result<U256> {
    let escrow_contract = IMockEscrow::new(escrow, provider);

    let fee = escrow_contract
        .quoteLayerZeroFee(dst_eid, token, amount, recipient, options)
        .call()
        .await?;

    Ok(fee.nativeFee)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_options_builder() {
        let options = OptionsBuilder::new().add_executor_lz_receive_option(200_000, 0).build();

        // Verify header
        assert_eq!(options[0], 0x00, "Invalid version byte 0");
        assert_eq!(options[1], 0x03, "Invalid version byte 1");
        assert_eq!(options[2], 0x01, "Invalid option type");
        assert_eq!(options[3], 32, "Invalid option length");

        // Verify gas value
        let gas_bytes = &options[4..20];
        let gas = u128::from_be_bytes(gas_bytes.try_into().unwrap());
        assert_eq!(gas, 200_000, "Invalid gas value");

        // Verify native drop (should be 0)
        let native_drop_bytes = &options[20..36];
        let native_drop = u128::from_be_bytes(native_drop_bytes.try_into().unwrap());
        assert_eq!(native_drop, 0, "Invalid native drop value");
    }
}
