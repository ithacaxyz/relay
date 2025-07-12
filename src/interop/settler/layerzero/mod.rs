use super::{SettlementError, Settler};
use crate::{
    interop::settler::layerzero::{
        contracts::{ILayerZeroEndpointV2, ILayerZeroSettler, MessagingParams, Origin},
        types::LayerZeroPacketInfo,
        utils::{bytes32_to_address, decode_packet, decode_packet_sent_event},
    },
    storage::{RelayStorage, StorageApi},
    transactions::{RelayTransaction, TransactionStatus, interop::InteropBundle},
};
use alloy::{
    primitives::{Address, B256, Bytes, ChainId, U256, keccak256, map::HashMap as AlloyHashMap},
    providers::{DynProvider, Provider},
    rpc::types::{Filter, TransactionReceipt, TransactionRequest, state::AccountOverride},
    sol_types::{SolCall, SolEvent, SolValue},
};
use async_trait::async_trait;
use futures_util::future::try_join_all;
use itertools::Itertools;
use std::{collections::HashMap, time::Duration};
use tokio::time::{Instant, sleep_until};
use tracing::{debug, info, instrument, warn};

/// LayerZero contract interfaces.
pub mod contracts;
/// LayerZero-specific types.
pub mod types;
/// Utility functions for LayerZero protocol integration.
pub mod utils;

/// Empty payload hash constant used by LayerZero to indicate no message.
const EMPTY_PAYLOAD_HASH: B256 = B256::ZERO;

/// LayerZero settler implementation for cross-chain settlement attestation.
#[derive(Debug)]
pub struct LayerZeroSettler {
    /// Chain ID to LayerZero endpoint ID mapping.
    endpoint_ids: AlloyHashMap<ChainId, u32>,
    /// Reverse mapping: endpoint ID to chain ID for efficient lookups.
    eid_to_chain: HashMap<u32, ChainId>,
    /// Chain ID to LayerZero endpoint address mapping.
    endpoint_addresses: AlloyHashMap<ChainId, Address>,
    /// Chain ID to provider mapping.
    providers: AlloyHashMap<ChainId, DynProvider>,
    /// On-chain settler contract address.
    settler_address: Address,
    /// Storage backend for persisting data.
    storage: RelayStorage,
}

impl LayerZeroSettler {
    /// Creates a new LayerZero settler with the given endpoint configurations.
    ///
    /// # Arguments
    ///
    /// * `endpoint_ids` - Mapping of chain ID to LayerZero endpoint ID
    /// * `endpoint_addresses` - Mapping of chain ID to LayerZero endpoint address
    /// * `providers` - Mapping of chain ID to provider instances
    /// * `settler_address` - The address of the LayerZero settler contract
    /// * `storage` - The storage backend for persisting data
    pub fn new(
        endpoint_ids: AlloyHashMap<ChainId, u32>,
        endpoint_addresses: AlloyHashMap<ChainId, Address>,
        providers: AlloyHashMap<ChainId, DynProvider>,
        settler_address: Address,
        storage: RelayStorage,
    ) -> Self {
        // Build the reverse mapping for O(1) endpoint ID to chain ID lookups
        let eid_to_chain = endpoint_ids.iter().map(|(chain_id, eid)| (*eid, *chain_id)).collect();

        Self { endpoint_ids, eid_to_chain, endpoint_addresses, providers, settler_address, storage }
    }

    /// Gets the LayerZero endpoint address for a given chain ID.
    pub fn get_endpoint_address(&self, chain_id: u64) -> Option<&Address> {
        self.endpoint_addresses.get(&chain_id)
    }

    /// Converts a LayerZero endpoint ID to a chain ID.
    fn eid_to_chain_id(&self, eid: u32) -> Result<u64, SettlementError> {
        self.eid_to_chain.get(&eid).copied().ok_or_else(|| SettlementError::UnknownEndpointId(eid))
    }

    /// Extracts packet information from a transaction receipt.
    fn extract_packet_from_receipt(
        &self,
        receipt: &TransactionReceipt,
        bundle_id: crate::types::rpc::BundleId,
    ) -> Result<Option<LayerZeroPacketInfo>, SettlementError> {
        // Look for PacketSent events in the logs
        for log in receipt.inner.logs() {
            // Check if this is a PacketSent event (topic[0] matches the event signature)
            if log.topics().is_empty() {
                continue;
            }

            // Try to decode as PacketSent event
            let decode_result = decode_packet_sent_event(log.data().data.as_ref(), log.topics());
            if let Ok((encoded_payload, _options, _send_library)) = decode_result {
                // Decode the packet from the encoded payload
                let packet = decode_packet(&encoded_payload)
                    .map_err(SettlementError::PacketExtractionError)?;

                // Convert endpoint IDs to chain IDs
                let src_chain_id = self.eid_to_chain_id(packet.src_eid)?;
                let dst_chain_id = self.eid_to_chain_id(packet.dst_eid)?;

                // Convert bytes32 addresses to Address
                let sender = bytes32_to_address(packet.sender)
                    .map_err(SettlementError::PacketExtractionError)?;
                let receiver = bytes32_to_address(packet.receiver)
                    .map_err(SettlementError::PacketExtractionError)?;

                return Ok(Some(LayerZeroPacketInfo {
                    bundle_id,
                    src_chain_id,
                    dst_chain_id,
                    nonce: packet.nonce,
                    sender,
                    receiver,
                    guid: packet.guid,
                    message: packet.message.into(),
                }));
            }
        }

        Ok(None)
    }

    /// Checks if a LayerZero message is verified and available for execute receive.
    async fn is_message_available(
        &self,
        packet: &LayerZeroPacketInfo,
    ) -> Result<bool, SettlementError> {
        // Get the provider for the destination chain
        let provider = self
            .providers
            .get(&packet.dst_chain_id)
            .ok_or_else(|| SettlementError::UnsupportedChain(packet.dst_chain_id))?;

        // Get the endpoint address for the destination chain
        let endpoint_address = self
            .endpoint_addresses
            .get(&packet.dst_chain_id)
            .ok_or_else(|| SettlementError::UnsupportedChain(packet.dst_chain_id))?;

        // Get the source endpoint ID
        let src_eid = self
            .endpoint_ids
            .get(&packet.src_chain_id)
            .ok_or_else(|| SettlementError::UnsupportedChain(packet.src_chain_id))?;

        // Create endpoint contract instance
        let endpoint = ILayerZeroEndpointV2::new(*endpoint_address, provider);

        // Convert sender address to bytes32
        let sender_bytes32 = B256::left_padding_from(packet.sender.as_slice());

        // Check the inbound payload hash
        let payload_hash = endpoint
            .inboundPayloadHash(packet.receiver, *src_eid, sender_bytes32, packet.nonce)
            .call()
            .await
            .map_err(|e| {
                SettlementError::ContractCallError(format!(
                    "Failed to check inbound payload hash: {e}"
                ))
            })?;

        // Message is available if the payload hash is not empty
        let is_available = payload_hash != EMPTY_PAYLOAD_HASH;

        debug!(
            packet_guid = ?packet.guid,
            payload_hash = ?payload_hash,
            is_available = is_available,
            "Message availability check complete"
        );

        Ok(is_available)
    }

    /// Builds a single LayerZero execute receive transaction.
    async fn build_execute_receive_transaction(
        &self,
        packet: &LayerZeroPacketInfo,
    ) -> Result<Option<RelayTransaction>, SettlementError> {
        debug!(
            packet_guid = ?packet.guid,
            dst_chain = packet.dst_chain_id,
            "Building execute receive transaction for packet"
        );

        // Get the endpoint address for the destination chain
        let endpoint_address = self
            .endpoint_addresses
            .get(&packet.dst_chain_id)
            .ok_or_else(|| SettlementError::UnsupportedChain(packet.dst_chain_id))?;

        // Get the provider for the destination chain
        let provider = self
            .providers
            .get(&packet.dst_chain_id)
            .ok_or_else(|| SettlementError::UnsupportedChain(packet.dst_chain_id))?;

        // Convert source chain ID to endpoint ID
        let src_eid = self
            .endpoint_ids
            .get(&packet.src_chain_id)
            .ok_or_else(|| SettlementError::UnsupportedChain(packet.src_chain_id))?;

        // Build the Origin struct
        let origin = Origin {
            srcEid: *src_eid,
            sender: B256::left_padding_from(packet.sender.as_slice()),
            nonce: packet.nonce,
        };

        // Build the lzReceive call
        let calldata = ILayerZeroEndpointV2::lzReceiveCall {
            _origin: origin,
            _receiver: packet.receiver,
            _guid: packet.guid,
            _message: packet.message.clone(),
            _extraData: Bytes::new(),
        }
        .abi_encode();

        // Estimate gas for the lzReceive call
        let from = Address::random();
        let tx_request = TransactionRequest {
            from: Some(from),
            to: Some((*endpoint_address).into()),
            value: None,
            input: calldata.clone().into(),
            ..Default::default()
        };

        let gas_limit = provider
            .estimate_gas(tx_request)
            .account_override(from, AccountOverride::default().with_balance(U256::MAX))
            .await?;

        // Add 20% buffer to the gas estimate
        let gas_limit = gas_limit.saturating_mul(120).saturating_div(100);

        let tx = RelayTransaction::new_internal(
            *endpoint_address,
            calldata,
            packet.dst_chain_id,
            gas_limit,
        );

        debug!(
            packet_guid = ?packet.guid,
            dst_chain = packet.dst_chain_id,
            endpoint = ?endpoint_address,
            gas_limit = gas_limit,
            "Built execute receive transaction for LayerZero packet"
        );

        Ok(Some(tx))
    }

    /// Extract packet infos from settlement transactions in the bundle.
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

        // Process each settlement transaction in parallel
        let packet_results = try_join_all(bundle.settlement_txs.iter().map(async |tx| {
            // Get transaction receipt from storage
            // Note: We can assume transactions are confirmed when called from SettlementsProcessing
            // state
            let (_, status) =
                self.storage.read_transaction_status(tx.id).await?.ok_or_else(|| {
                    SettlementError::PacketExtractionError(
                        "Transaction status not found".to_string(),
                    )
                })?;

            // Extract the receipt - we expect all settlements to be confirmed at this point
            let receipt = match status {
                TransactionStatus::Confirmed(receipt) => receipt,
                _ => {
                    return Err(SettlementError::UnexpectedTransactionState {
                        expected: "confirmed",
                        actual: format!("{status:?}"),
                    });
                }
            };

            // Extract packet info from receipt logs
            self.extract_packet_from_receipt(&receipt, bundle.id)
        }))
        .await?;

        // Filter out None values and collect packet infos
        let packet_infos: Vec<LayerZeroPacketInfo> = packet_results.into_iter().flatten().collect();

        Ok(packet_infos)
    }
}

#[async_trait]
impl Settler for LayerZeroSettler {
    fn id(&self) -> &'static str {
        "layer_zero"
    }

    fn address(&self) -> Address {
        self.settler_address
    }

    #[instrument(skip(self), fields(settler_id = %self.id()))]
    async fn build_execute_send_transaction(
        &self,
        settlement_id: B256,
        current_chain_id: u64,
        source_chains: Vec<u64>,
        orchestrator: Address,
    ) -> Result<Option<RelayTransaction>, SettlementError> {
        let settler_context = self.encode_settler_context(source_chains.clone())?;

        // Get the provider and endpoint address for the current chain
        let provider = self
            .providers
            .get(&current_chain_id)
            .ok_or_else(|| SettlementError::UnsupportedChain(current_chain_id))?;

        let endpoint_address = self
            .endpoint_addresses
            .get(&current_chain_id)
            .ok_or_else(|| SettlementError::UnsupportedChain(current_chain_id))?;

        // Create endpoint contract instance
        let endpoint = ILayerZeroEndpointV2::new(*endpoint_address, provider);

        // Build all messaging params
        let all_params = source_chains
            .iter()
            .map(|source_chain_id| {
                // Get the endpoint ID for this source chain (dst_eid in the quote context)
                let dst_eid = self
                    .endpoint_ids
                    .get(source_chain_id)
                    .ok_or_else(|| SettlementError::UnsupportedChain(*source_chain_id))?;

                // Build messaging params
                Ok(MessagingParams {
                    dstEid: *dst_eid,
                    receiver: B256::left_padding_from(self.settler_address.as_slice()),
                    message: (settlement_id, self.settler_address, U256::from(*source_chain_id))
                        .abi_encode()
                        .into(),
                    options: Bytes::new(),
                    payInLzToken: false,
                })
            })
            .collect::<Result<Vec<_>, SettlementError>>()?;

        // Quote for all chain fees.
        let multicall =
            all_params.iter().fold(provider.multicall().dynamic(), |multicall, params| {
                multicall.add_dynamic(endpoint.quote(params.clone(), self.settler_address))
            });

        let native_lz_fee: U256 =
            multicall.aggregate().await?.into_iter().map(|fee| fee.nativeFee).sum();

        let calldata = ILayerZeroSettler::executeSendCall {
            sender: orchestrator,
            settlementId: settlement_id,
            settlerContext: settler_context,
        }
        .abi_encode();

        // Create an internal transaction for the settlement with the calculated gas
        let provider = self
            .providers
            .get(&current_chain_id)
            .ok_or_else(|| SettlementError::UnsupportedChain(current_chain_id))?;

        let from = Address::random();
        let tx_request = TransactionRequest {
            from: Some(from),
            to: Some(self.settler_address.into()),
            value: Some(native_lz_fee),
            input: calldata.clone().into(),
            ..Default::default()
        };

        let gas_limit = provider
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
            .map(|chain_id| {
                // Validate we have both endpoint ID and address for this chain
                if !self.endpoint_addresses.contains_key(&chain_id) {
                    return Err(SettlementError::UnsupportedChain(chain_id));
                }

                self.endpoint_ids
                    .get(&chain_id)
                    .copied()
                    .ok_or_else(|| SettlementError::UnsupportedChain(chain_id))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Encode the endpoint IDs as a dynamic array of uint32
        Ok(endpoint_ids.abi_encode().into())
    }

    async fn wait_for_verifications(
        &self,
        bundle: &InteropBundle,
        timeout: Duration,
    ) -> Result<bool, SettlementError> {
        // Extract packet infos from bundle
        let packet_infos = self.extract_packet_infos(bundle).await?;

        if packet_infos.is_empty() {
            return Ok(true);
        }

        let deadline = Instant::now() + timeout;

        info!(
            num_packets = packet_infos.len(),
            timeout_secs = timeout.as_secs(),
            "Waiting for LayerZero message verifications"
        );

        // Group packets by destination chain
        let packets_by_chain = self.group_packets_by_chain(packet_infos);

        // Set up event subscriptions for all chains
        let chain_monitors = self.setup_chain_monitors(packets_by_chain).await?;

        // Small delay to ensure subscriptions are fully established
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check which messages are already verified
        let (already_verified_count, pending_by_chain) =
            self.check_initial_verification_status(&chain_monitors).await?;

        if pending_by_chain.is_empty() {
            info!("All {} messages already verified", already_verified_count);
            return Ok(true);
        }

        // Monitor pending messages until deadline
        let verified_via_events =
            self.monitor_pending_messages(&pending_by_chain, chain_monitors, deadline).await?;

        // Final verification check if we timed out
        let all_verified =
            self.final_verification_check(verified_via_events, &pending_by_chain).await?;

        Ok(all_verified)
    }

    async fn build_execute_receive_transactions(
        &self,
        bundle: &InteropBundle,
    ) -> Result<Vec<RelayTransaction>, SettlementError> {
        // Extract packet infos and filter for verified ones
        let all_packet_infos = self.extract_packet_infos(bundle).await?;

        if all_packet_infos.is_empty() {
            return Ok(vec![]);
        }

        // Check which packets are actually available for execute receive in parallel
        let availability_results = try_join_all(all_packet_infos.iter().map(async |packet| {
            let is_available = self.is_message_available(packet).await?;
            Ok::<_, SettlementError>((packet.clone(), is_available))
        }))
        .await?;

        let packet_infos: Vec<LayerZeroPacketInfo> = availability_results
            .into_iter()
            .filter_map(|(packet, is_available)| if is_available { Some(packet) } else { None })
            .collect();

        info!(num_packets = packet_infos.len(), "Building LayerZero execute receive transactions");

        // Build execute receive transactions in parallel
        let execute_receive_results = try_join_all(
            packet_infos.iter().map(|packet| self.build_execute_receive_transaction(packet)),
        )
        .await?;

        // Filter out any None results
        let execute_receive_txs: Vec<RelayTransaction> =
            execute_receive_results.into_iter().flatten().collect();

        info!(
            num_deliveries = execute_receive_txs.len(),
            "Successfully built execute receive transactions"
        );

        Ok(execute_receive_txs)
    }
}

/// Represents a chain's monitoring context
struct ChainMonitor {
    /// Chain ID for this monitor
    chain_id: u64,
    /// LayerZero endpoint address on this chain
    endpoint_address: Address,
    /// Event subscription stream (None if WebSocket unavailable)
    stream: Option<alloy::pubsub::Subscription<alloy::rpc::types::Log>>,
    /// Packets to monitor on this chain
    packets: Vec<LayerZeroPacketInfo>,
}

impl LayerZeroSettler {
    /// Groups packets by their destination chain
    fn group_packets_by_chain(
        &self,
        packets: Vec<LayerZeroPacketInfo>,
    ) -> HashMap<u64, Vec<LayerZeroPacketInfo>> {
        let mut packets_by_chain: HashMap<u64, Vec<LayerZeroPacketInfo>> = HashMap::new();
        for packet in packets {
            packets_by_chain.entry(packet.dst_chain_id).or_default().push(packet);
        }
        packets_by_chain
    }

    /// Sets up event monitors for all chains
    async fn setup_chain_monitors(
        &self,
        packets_by_chain: HashMap<u64, Vec<LayerZeroPacketInfo>>,
    ) -> Result<Vec<ChainMonitor>, SettlementError> {
        let subscription_tasks: Vec<_> = packets_by_chain
            .into_iter()
            .map(|(chain_id, packets)| {
                let provider = self.providers.get(&chain_id).cloned();
                let endpoint_address = self.endpoint_addresses.get(&chain_id).copied();

                tokio::spawn(async move {
                    let provider =
                        provider.ok_or_else(|| SettlementError::UnsupportedChain(chain_id))?;
                    let endpoint_address = endpoint_address
                        .ok_or_else(|| SettlementError::UnsupportedChain(chain_id))?;

                    // Try to subscribe to events
                    let filter = Filter::new()
                        .address(endpoint_address)
                        .event_signature(ILayerZeroEndpointV2::PacketVerified::SIGNATURE_HASH);

                    let stream = match provider.subscribe_logs(&filter).await {
                        Ok(stream) => {
                            info!(chain_id, "Successfully subscribed to PacketVerified events");
                            Some(stream)
                        }
                        Err(e) => {
                            warn!(
                                chain_id,
                                error = ?e,
                                "Failed to subscribe to events, will use polling fallback"
                            );
                            None
                        }
                    };

                    Ok::<_, SettlementError>(ChainMonitor {
                        chain_id,
                        endpoint_address,
                        stream,
                        packets,
                    })
                })
            })
            .collect();

        // Collect all monitors
        let mut monitors = Vec::new();
        for task in subscription_tasks {
            match task.await {
                Ok(Ok(monitor)) => monitors.push(monitor),
                Ok(Err(e)) => return Err(e),
                Err(e) => {
                    warn!(error = ?e, "Subscription setup task panicked");
                    return Err(SettlementError::ContractCallError(format!("Task panic: {e}")));
                }
            }
        }

        info!(num_chains = monitors.len(), "Event monitors established for chains");

        Ok(monitors)
    }

    /// Checks initial verification status and returns already verified count and pending packets
    async fn check_initial_verification_status(
        &self,
        monitors: &[ChainMonitor],
    ) -> Result<(usize, HashMap<u64, Vec<LayerZeroPacketInfo>>), SettlementError> {
        let mut already_verified_count = 0;
        let mut pending_by_chain: HashMap<u64, Vec<LayerZeroPacketInfo>> = HashMap::new();

        for monitor in monitors {
            let mut pending = Vec::new();
            for packet in &monitor.packets {
                if !self.is_message_available(packet).await? {
                    pending.push(packet.clone());
                } else {
                    already_verified_count += 1;
                }
            }

            info!(
                chain_id = monitor.chain_id,
                has_stream = monitor.stream.is_some(),
                total_packets = monitor.packets.len(),
                pending_packets = pending.len(),
                already_verified = monitor.packets.len() - pending.len(),
                "Initial verification status"
            );

            if !pending.is_empty() {
                pending_by_chain.insert(monitor.chain_id, pending);
            }
        }

        Ok((already_verified_count, pending_by_chain))
    }

    /// Monitors pending messages across all chains until deadline
    async fn monitor_pending_messages(
        &self,
        pending_by_chain: &HashMap<u64, Vec<LayerZeroPacketInfo>>,
        monitors: Vec<ChainMonitor>,
        deadline: Instant,
    ) -> Result<Vec<B256>, SettlementError> {
        let mut monitoring_tasks = Vec::new();

        for monitor in monitors {
            if let Some(pending_packets) = pending_by_chain.get(&monitor.chain_id) {
                if pending_packets.is_empty() {
                    continue;
                }

                let packets = pending_packets.clone();

                let task = tokio::spawn(async move {
                    match monitor.stream {
                        Some(stream) => {
                            info!(
                                chain_id = monitor.chain_id,
                                num_pending = packets.len(),
                                "Monitoring chain with event stream"
                            );
                            monitor_packet_stream(
                                stream,
                                monitor.endpoint_address,
                                packets,
                                deadline,
                            )
                            .await
                        }
                        None => {
                            warn!(
                                chain_id = monitor.chain_id,
                                "No event stream available, waiting until deadline"
                            );
                            tokio::time::sleep_until(deadline).await;
                            Ok(vec![])
                        }
                    }
                });
                monitoring_tasks.push(task);
            }
        }

        // Collect results from all monitoring tasks
        let mut all_verified_guids = Vec::new();
        for task in monitoring_tasks {
            match task.await {
                Ok(Ok(verified_guids)) => all_verified_guids.extend(verified_guids),
                Ok(Err(e)) => warn!(error = ?e, "Monitoring task failed"),
                Err(e) => warn!(error = ?e, "Monitoring task panicked"),
            }
        }

        if !all_verified_guids.is_empty() {
            info!(count = all_verified_guids.len(), "Messages verified via event monitoring");
        }

        Ok(all_verified_guids)
    }

    /// Final verification check for any remaining unverified messages
    async fn final_verification_check(
        &self,
        verified_guids: Vec<B256>,
        pending_by_chain: &HashMap<u64, Vec<LayerZeroPacketInfo>>,
    ) -> Result<bool, SettlementError> {
        let total_pending: usize = pending_by_chain.values().map(|v| v.len()).sum();
        let verified_via_events = verified_guids.len();

        // If we verified everything via events, we're done
        if verified_via_events >= total_pending {
            return Ok(true);
        }

        // We timed out - do a final check on remaining messages
        info!(
            verified_via_events,
            total_pending, "Timeout reached, performing final verification check"
        );

        let mut final_verified_count = 0;
        for packets in pending_by_chain.values() {
            for packet in packets {
                // Skip packets we already verified via events
                if verified_guids.contains(&packet.guid) {
                    continue;
                }

                if self.is_message_available(packet).await? {
                    final_verified_count += 1;
                }
            }
        }

        if final_verified_count > 0 {
            info!(count = final_verified_count, "Additional messages verified in final check");
        }

        let total_verified = verified_via_events + final_verified_count;
        Ok(total_verified >= total_pending)
    }
}

/// Monitor a stream for packet verifications
async fn monitor_packet_stream(
    mut stream: alloy::pubsub::Subscription<alloy::rpc::types::Log>,
    endpoint_address: Address,
    packets: Vec<LayerZeroPacketInfo>,
    deadline: Instant,
) -> Result<Vec<B256>, SettlementError> {
    // Precalculate payload hashes
    let packet_lookup: HashMap<(u64, Address, B256), B256> = packets
        .iter()
        .map(|packet| {
            let payload = [packet.guid.as_slice(), packet.message.as_ref()].concat();
            let payload_hash = keccak256(&payload);

            info!(
                guid = ?packet.guid,
                nonce = packet.nonce,
                receiver = ?packet.receiver,
                payload_hash = ?payload_hash,
                "Prepared packet for monitoring"
            );
            ((packet.nonce, packet.receiver, payload_hash), packet.guid)
        })
        .collect();

    let mut verified_guids = Vec::new();
    let mut remaining = packets.len();

    info!(
        endpoint = ?endpoint_address,
        num_packets = packets.len(),
        timeout_secs = (deadline - Instant::now()).as_secs(),
        "Starting PacketVerified event monitoring"
    );

    while remaining > 0 && Instant::now() < deadline {
        tokio::select! {
            result = stream.recv() => {
                match result {
                    Ok(log) => {
                        info!(
                            log_address = ?log.inner.address,
                            "Received log event"
                        );

                        match ILayerZeroEndpointV2::PacketVerified::decode_log(&log.inner) {
                            Ok(event) => {
                                info!(
                                    event_nonce = event.origin.nonce,
                                    event_receiver = ?event.receiver,
                                    event_payload_hash = ?event.payloadHash,
                                    event_src_eid = event.origin.srcEid,
                                    event_sender = ?event.origin.sender,
                                    "Decoded PacketVerified event"
                                );

                                // Look up packet by event data
                                let lookup_key = (event.origin.nonce, event.receiver, event.payloadHash);

                                if let Some(guid) = packet_lookup.get(&lookup_key) {
                                    verified_guids.push(*guid);
                                    remaining -= 1;
                                    info!(
                                        ?guid,
                                        nonce = event.origin.nonce,
                                        receiver = ?event.receiver,
                                        remaining,
                                        "Message verified via event"
                                    );
                                } else {
                                    warn!(
                                        event_nonce = event.origin.nonce,
                                        event_receiver = ?event.receiver,
                                        event_payload_hash = ?event.payloadHash,
                                        "Received PacketVerified event but no matching packet in lookup"
                                    );
                                }
                            }
                            Err(e) => {
                                warn!(
                                    error = ?e,
                                    "Failed to decode PacketVerified event"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        warn!(
                            error = ?e,
                            "Stream receive error"
                        );
                        break;
                    }
                }
            }
            _ = sleep_until(deadline) => {
                info!(
                    remaining,
                    verified = verified_guids.len(),
                    "Verification monitoring timed out"
                );
                break;
            }
        }
    }

    info!(verified_count = verified_guids.len(), remaining, "Completed event monitoring");

    Ok(verified_guids)
}
