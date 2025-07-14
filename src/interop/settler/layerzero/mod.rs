//! # LayerZero Protocol Integration
//!
//! This module implements the LayerZero settler for cross-chain settlement attestation in the
//! Ithaca Relay. LayerZero is an omnichain interoperability protocol that enables secure message
//! passing between blockchains.
//!
//! ## Overview
//!
//! The LayerZero integration allows the relay to:
//! - Send cross-chain settlement attestations via LayerZero's messaging protocol
//! - Monitor and verify message delivery across chains
//! - Execute received messages to complete settlement flows
//!
//! ## Cross-Chain Settlement Flow
//!
//! 1. **Settlement Initiation**: When a settlement needs to be attested across chains, the relay
//!    calls `build_execute_send_transaction` to create a transaction that sends LayerZero messages
//!    to all destination chains.
//!
//! 2. **Message Transmission**: The LayerZero endpoint on the source chain emits `PacketSent`
//!    events containing the encoded message payload and routing information.
//!
//! 3. **Off-Chain Verification**: LayerZero's decentralized verifier network (DVNs) observes the
//!    source chain event and attests to its validity on the destination chains.
//!
//! 4. **Message Availability**: Once verified, the message becomes available on the destination
//!    chain's LayerZero endpoint, indicated by a non-zero `inboundPayloadHash`.
//!
//! 5. **Message Execution**: The relay monitors for message verification and builds `lzReceive`
//!    transactions to execute the delivered messages on each destination chain.
//!
//! ## Key Concepts
//!
//! - **Endpoint ID (EID)**: Each blockchain in the LayerZero network has a unique endpoint ID
//! - **GUID**: Globally Unique Identifier for each LayerZero packet
//! - **Nonce**: Per-sender ordering mechanism to ensure message sequencing
//! - **DVN**: Decentralized Verifier Network that attests to cross-chain messages
//! - **Packet**: The unit of cross-chain communication containing routing info and payload

use super::{SettlementError, Settler, SettlerId};
use crate::{
    constants::MULTICALL3_ADDRESS,
    interop::{
        EscrowDetails,
        settler::layerzero::{
            contracts::{
                ILayerZeroEndpointV2::{self, PacketSent},
                ILayerZeroSettler, MessagingParams,
            },
            types::{LayerZeroPacketInfo, LayerZeroPacketV1},
        },
    },
    storage::{RelayStorage, StorageApi},
    transactions::{RelayTransaction, TransactionStatus, interop::InteropBundle},
    types::{Call3, IEscrow, aggregate3Call},
};
use alloy::{
    primitives::{Address, B256, Bytes, ChainId, U256, map::HashMap},
    providers::{DynProvider, Provider},
    rpc::types::{TransactionReceipt, TransactionRequest, state::AccountOverride},
    sol_types::{SolCall, SolEvent, SolValue},
};
use async_trait::async_trait;
use futures_util::future::try_join_all;
use itertools::Itertools;
use std::{sync::Arc, time::Duration};
use tracing::{debug, info, instrument};

/// LayerZero contract interfaces.
pub mod contracts;
/// LayerZero-specific types.
pub mod types;
/// Verification monitoring logic.
pub mod verification;
use verification::{LayerZeroVerificationMonitor, VerificationResult, is_message_available};

/// Empty payload hash constant used by LayerZero to indicate no message.
pub(super) const EMPTY_PAYLOAD_HASH: B256 = B256::ZERO;

/// Layerzero configuration for a specific chain.
#[derive(Debug, Clone)]
pub(super) struct LZChainConfig {
    /// LayerZero endpoint ID for this chain.
    pub endpoint_id: u32,
    /// LayerZero endpoint address for this chain.
    pub endpoint_address: Address,
    /// Provider for this chain.
    pub provider: DynProvider,
}

/// LayerZero settler implementation for cross-chain settlement attestation.
#[derive(Debug)]
pub struct LayerZeroSettler {
    /// Reverse mapping: endpoint ID to chain ID for efficient lookups.
    eid_to_chain: HashMap<u32, ChainId>,
    /// Chain ID to LayerZero endpoint address mapping.
    endpoint_addresses: HashMap<ChainId, Address>,
    /// On-chain settler contract address.
    settler_address: Address,
    /// Storage backend for persisting data.
    storage: RelayStorage,
    /// Chain configurations.
    chain_configs: Arc<HashMap<ChainId, LZChainConfig>>,
}

impl LayerZeroSettler {
    /// Creates a new LayerZero settler instance for cross-chain settlement attestation.
    pub fn new(
        endpoint_ids: HashMap<ChainId, u32>,
        endpoint_addresses: HashMap<ChainId, Address>,
        providers: HashMap<ChainId, DynProvider>,
        settler_address: Address,
        storage: RelayStorage,
    ) -> Self {
        // Build the reverse mapping for O(1) endpoint ID to chain ID lookups
        let eid_to_chain = endpoint_ids.iter().map(|(chain_id, eid)| (*eid, *chain_id)).collect();

        // Build chain configs
        let chain_configs = endpoint_ids
            .keys()
            .filter_map(|chain_id| {
                let endpoint_id = endpoint_ids.get(chain_id)?;
                let endpoint_address = endpoint_addresses.get(chain_id)?;
                let provider = providers.get(chain_id)?;

                Some((
                    *chain_id,
                    LZChainConfig {
                        endpoint_id: *endpoint_id,
                        endpoint_address: *endpoint_address,
                        provider: provider.clone(),
                    },
                ))
            })
            .collect();

        Self {
            eid_to_chain,
            endpoint_addresses,
            settler_address,
            storage,
            chain_configs: Arc::new(chain_configs),
        }
    }

    /// Gets the LayerZero endpoint address for a given chain ID.
    pub fn get_endpoint_address(&self, chain_id: u64) -> Option<&Address> {
        self.endpoint_addresses.get(&chain_id)
    }

    /// Gets the cached chain configuration for a given chain ID.
    fn get_chain_config(&self, chain_id: u64) -> Result<&LZChainConfig, SettlementError> {
        self.chain_configs.get(&chain_id).ok_or_else(|| SettlementError::UnsupportedChain(chain_id))
    }

    /// Converts a LayerZero endpoint ID to a chain ID.
    fn eid_to_chain_id(&self, eid: u32) -> Result<u64, SettlementError> {
        self.eid_to_chain.get(&eid).copied().ok_or_else(|| SettlementError::UnknownEndpointId(eid))
    }

    /// Extracts all packet information from a transaction receipt.
    fn extract_packets_from_receipt(
        &self,
        receipt: &TransactionReceipt,
    ) -> Result<Vec<LayerZeroPacketInfo>, SettlementError> {
        let mut packets = Vec::new();

        // Look for PacketSent events in the logs
        for log in receipt.inner.logs() {
            // Check if this is a PacketSent event (topic[0] matches the event signature)
            if log.topics().is_empty() {
                continue;
            }

            if let Ok(event) = PacketSent::decode_raw_log(log.topics(), log.data().data.as_ref()) {
                // Decode the packet from the encoded payload
                let packet = LayerZeroPacketV1::decode(&event.encodedPayload)
                    .map_err(SettlementError::InternalError)?;

                let src_chain_id = self.eid_to_chain_id(packet.src_eid)?;
                let dst_chain_id = self.eid_to_chain_id(packet.dst_eid)?;

                let sender = Address::from_slice(&packet.sender[12..]);
                let receiver = Address::from_slice(&packet.receiver[12..]);

                packets.push(LayerZeroPacketInfo {
                    src_chain_id,
                    dst_chain_id,
                    nonce: packet.nonce,
                    sender,
                    receiver,
                    guid: packet.guid,
                    message: packet.message.into(),
                });
            }
        }

        Ok(packets)
    }

    /// Builds a transaction to execute a single verified LayerZero message.
    ///
    /// This method constructs a multicall transaction that:
    /// 1. Calls `lzReceive` to complete the LayerZero message delivery
    /// 2. Calls `Escrow.settle` to release the escrowed funds
    ///
    /// ## Note
    ///
    /// This method assumes the message has already been verified. Always check
    /// `is_message_available` before building the execute transaction.
    async fn build_execute_receive_transaction(
        &self,
        packet: &LayerZeroPacketInfo,
        bundle: &InteropBundle,
    ) -> Result<RelayTransaction, SettlementError> {
        debug!(
            packet_guid = ?packet.guid,
            dst_chain = packet.dst_chain_id,
            "Building multicall execute receive transaction"
        );

        let dst_config = self.get_chain_config(packet.dst_chain_id)?;
        let src_config = self.get_chain_config(packet.src_chain_id)?;

        // Build the LayerZero receive call
        let lz_receive_call = packet.build_lz_receive_call(src_config.endpoint_id);

        // Extract and filter escrows for this settlement
        let settlement_id = packet.settlement_id().map_err(SettlementError::InternalError)?;
        let (escrow_ids, escrow_address) = get_escrows(bundle, packet.dst_chain_id, settlement_id)?;

        let multicall_calldata = build_multicall_data(
            &lz_receive_call,
            dst_config.endpoint_address,
            &escrow_ids,
            escrow_address,
        )?;

        let tx_request = TransactionRequest {
            to: Some(MULTICALL3_ADDRESS.into()),
            value: None,
            input: multicall_calldata.clone().into(),
            ..Default::default()
        };

        let gas_limit = dst_config.provider.estimate_gas(tx_request).await?;

        let tx = RelayTransaction::new_internal(
            MULTICALL3_ADDRESS,
            multicall_calldata,
            packet.dst_chain_id,
            gas_limit,
        );

        debug!(
            packet_guid = ?packet.guid,
            dst_chain = packet.dst_chain_id,
            num_escrows = escrow_ids.len(),
            gas_limit = gas_limit,
            "Built multicall execute receive transaction"
        );

        Ok(tx)
    }

    /// Extracts LayerZero packet information from settlement transaction receipts.
    ///
    /// This method parses transaction receipts to find `PacketSent` events emitted by
    /// LayerZero endpoints during the settlement sending phase. Each event contains
    /// the full packet information needed to track and execute the cross-chain message.
    async fn extract_packet_infos(
        &self,
        bundle: &InteropBundle,
    ) -> Result<Vec<LayerZeroPacketInfo>, SettlementError> {
        if bundle.settlement_txs.is_empty() {
            return Ok(vec![]);
        }

        info!(
            bundle_id = ?bundle.id,
            num_settlements = bundle.settlement_txs.len(),
            "Extracting LayerZero packet info from settlement receipts"
        );

        // Process each settlement transaction
        let packet_results = try_join_all(bundle.settlement_txs.iter().map(async |tx| {
            // Get transaction receipt from storage
            // Note: We can assume transactions are confirmed when called from SettlementsProcessing
            // state
            let (_, status) =
                self.storage.read_transaction_status(tx.id).await?.ok_or_else(|| {
                    SettlementError::InternalError("Transaction status not found".to_string())
                })?;

            let receipt = match status {
                TransactionStatus::Confirmed(receipt) => receipt,
                _ => unreachable!("we only process settlements if transactions are confirmed"),
            };

            // Extract packet info from receipt logs
            self.extract_packets_from_receipt(&receipt)
        }))
        .await?;

        // Flatten all packet vectors into a single vector
        let packet_infos: Vec<LayerZeroPacketInfo> = packet_results.into_iter().flatten().collect();

        Ok(packet_infos)
    }
}

#[async_trait]
impl Settler for LayerZeroSettler {
    fn id(&self) -> SettlerId {
        SettlerId::LayerZero
    }

    fn address(&self) -> Address {
        self.settler_address
    }

    /// Builds a transaction to send settlement attestations to multiple destination chains via
    /// LayerZero.
    ///
    /// This method creates a single transaction that will send LayerZero messages to all specified
    /// source chains, notifying them about a settlement that occurred on the current chain. It will
    /// attach a msg.value to pay for the DVNs to attest to this event.
    #[instrument(skip(self), fields(settler_id = %self.id()))]
    async fn build_execute_send_transaction(
        &self,
        settlement_id: B256,
        current_chain_id: u64,
        source_chains: Vec<u64>,
        orchestrator: Address,
    ) -> Result<Option<RelayTransaction>, SettlementError> {
        let settler_context = self.encode_settler_context(source_chains.clone())?;

        let current_config = self.get_chain_config(current_chain_id)?;

        // Create endpoint contract instance
        let endpoint =
            ILayerZeroEndpointV2::new(current_config.endpoint_address, &current_config.provider);

        // Build multicall for fee quotes
        let mut multicall = current_config.provider.multicall().dynamic();

        for source_chain_id in &source_chains {
            let src_config = self.get_chain_config(*source_chain_id)?;

            let params = MessagingParams {
                dstEid: src_config.endpoint_id,
                receiver: B256::left_padding_from(self.settler_address.as_slice()),
                message: (settlement_id, self.settler_address, U256::from(*source_chain_id))
                    .abi_encode()
                    .into(),
                options: Bytes::new(),
                payInLzToken: false,
            };

            multicall = multicall.add_dynamic(endpoint.quote(params, self.settler_address));
        }

        let native_lz_fee: U256 =
            multicall.aggregate().await?.into_iter().map(|fee| fee.nativeFee).sum();

        let calldata = ILayerZeroSettler::executeSendCall {
            sender: orchestrator,
            settlementId: settlement_id,
            settlerContext: settler_context,
        }
        .abi_encode();

        // Create a transaction for the settlement with the calculated gas with native_lz_fee
        let from = Address::random();
        let tx_request = TransactionRequest {
            from: Some(from),
            to: Some(self.settler_address.into()),
            value: Some(native_lz_fee),
            input: calldata.clone().into(),
            ..Default::default()
        };

        let gas_limit = current_config
            .provider
            .estimate_gas(tx_request)
            .account_override(from, AccountOverride::default().with_balance(U256::MAX))
            .await?;

        // Add 20% buffer to the gas estimate
        let gas_limit = gas_limit.saturating_mul(120).saturating_div(100);

        let tx = RelayTransaction::new_internal_with_value(
            self.settler_address,
            calldata,
            current_chain_id,
            gas_limit,
            native_lz_fee,
        );

        Ok(Some(tx))
    }

    fn encode_settler_context(
        &self,
        destination_chains: Vec<u64>,
    ) -> Result<Bytes, SettlementError> {
        let endpoint_ids: Vec<u32> = destination_chains
            .into_iter()
            .sorted()
            .map(|chain_id| self.get_chain_config(chain_id).map(|c| c.endpoint_id))
            .collect::<Result<Vec<_>, _>>()?;

        // Encode the endpoint IDs as a dynamic array of uint32
        Ok(endpoint_ids.abi_encode().into())
    }

    /// Waits for LayerZero messages to be verified on their destination chains.
    ///
    /// This method monitors the verification status of all LayerZero packets sent as part of
    /// the settlement process. It uses both event monitoring (via WebSocket when available)
    /// and polling fallbacks to track when messages become available for execution.
    ///
    /// # Verification Process
    ///
    /// 1. Extracts packet information from settlement transaction receipts
    /// 2. Groups packets by destination chain for efficient monitoring
    /// 3. Sets up event subscriptions for `PacketVerified` events.
    /// 4. Falls back to polling `inboundPayloadHash` for chains without WebSocket
    /// 5. Returns early if all messages are already verified
    ///
    /// ```
    async fn wait_for_verifications(
        &self,
        bundle: &InteropBundle,
        timeout: Duration,
    ) -> Result<VerificationResult, SettlementError> {
        // Extract packet infos from bundle
        let packet_infos = self.extract_packet_infos(bundle).await?;
        LayerZeroVerificationMonitor::new(self.chain_configs.clone())
            .wait_for_verifications(packet_infos, timeout.as_secs())
            .await
    }

    /// Builds transactions to execute verified LayerZero messages on their destination chains.
    ///
    /// This method creates `lzReceive` transactions for all verified messages, allowing the
    /// destination chain contracts to process the settlement attestations.
    async fn build_execute_receive_transactions(
        &self,
        bundle: &InteropBundle,
    ) -> Result<Vec<RelayTransaction>, SettlementError> {
        // Extract packet infos and filter for verified ones
        let all_packet_infos = self.extract_packet_infos(bundle).await?;

        if all_packet_infos.is_empty() {
            return Ok(vec![]);
        }

        // Check which packets are actually available for execute receive
        let availability_results: Vec<bool> = try_join_all(
            all_packet_infos
                .iter()
                .map(async |packet| is_message_available(packet, &self.chain_configs).await),
        )
        .await?;

        // Filter packets based on availability results
        let packet_infos: Vec<LayerZeroPacketInfo> = all_packet_infos
            .into_iter()
            .zip(availability_results)
            .filter_map(|(packet, is_available)| if is_available { Some(packet) } else { None })
            .collect();

        info!(num_packets = packet_infos.len(), "Building LayerZero execute receive transactions");

        // Build execute receive transactions
        let execute_receive_txs = try_join_all(
            packet_infos
                .iter()
                .map(|packet| self.build_execute_receive_transaction(packet, bundle)),
        )
        .await?;

        info!(
            num_deliveries = execute_receive_txs.len(),
            "Successfully built execute receive transactions"
        );

        Ok(execute_receive_txs)
    }
}

/// Extracts relevant escrowIds and escrowAddress for a specific settlement on a destination chain.
fn get_escrows(
    bundle: &InteropBundle,
    dst_chain_id: ChainId,
    settlement_id: B256,
) -> Result<(Vec<B256>, Address), SettlementError> {
    let escrow_details: Vec<EscrowDetails> =
        bundle.src_txs.iter().filter_map(|tx| tx.extract_escrow_details()).collect();

    // Filter escrows for this specific settlement and chain
    let escrow_ids: Vec<B256> = escrow_details
        .iter()
        .filter(|escrow| {
            escrow.chain_id == dst_chain_id && escrow.escrow.settlementId == settlement_id
        })
        .map(|escrow| escrow.escrow_id)
        .collect();

    // Find the escrow contract address for this chain
    let escrow_address = escrow_details
        .iter()
        .find(|e| e.chain_id == dst_chain_id)
        .map(|e| e.escrow_address)
        .ok_or_else(|| {
            SettlementError::InternalError(format!(
                "No escrow address found for chain {dst_chain_id}"
            ))
        })?;

    Ok((escrow_ids, escrow_address))
}

/// Builds the multicall data for executing LayerZero receive and escrow settlement.
///
/// This function creates a multicall that:
/// 1. Executes the LayerZero receive call to process the cross-chain message
/// 2. Settles the escrows to release funds
fn build_multicall_data(
    lz_receive_call: &ILayerZeroEndpointV2::lzReceiveCall,
    endpoint_address: Address,
    escrow_ids: &[B256],
    escrow_address: Address,
) -> Result<Bytes, SettlementError> {
    // Encode the LayerZero receive call
    let lz_receive_calldata = lz_receive_call.abi_encode();

    // Encode the escrow settle call
    let settle_calldata = IEscrow::settleCall { escrowIds: escrow_ids.to_vec() }.abi_encode();

    // Build the multicall
    let calls = vec![
        Call3 {
            target: endpoint_address,
            allowFailure: false,
            callData: lz_receive_calldata.into(),
        },
        Call3 { target: escrow_address, allowFailure: false, callData: settle_calldata.into() },
    ];

    let multicall_calldata = aggregate3Call { calls }.abi_encode();
    Ok(multicall_calldata.into())
}
