//! # LayerZero Verification Monitoring
//!
//! This module handles the monitoring and verification of LayerZero messages across chains.
//! It implements both event-based monitoring (when WebSocket connections are available) and
//! polling-based fallbacks to ensure reliable message verification tracking.
//!
//! ## Verification Process
//!
//! When a LayerZero message is sent from a source chain to a destination chain:
//!
//! 1. The source chain emits a `PacketSent` event containing the message details
//! 2. LayerZero's Decentralized Verifier Networks (DVNs) observe and verify the message
//! 3. Once verified, the destination chain's endpoint emits a `PacketVerified` event
//! 4. The message becomes available for execution (non-zero `inboundPayloadHash`)

use crate::interop::settler::{SettlementError, layerzero::types::LayerZeroPacketInfo};
use alloy::{
    primitives::{Address, B256, ChainId, keccak256, map::HashMap},
    providers::Provider,
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use futures_util::future::try_join_all;
use tokio::time::{Duration, Instant, sleep_until};
use tracing::{info, warn};

use super::contracts::IReceiveUln302;
use crate::types::LZChainConfigs;

/// Result of verification monitoring for LayerZero messages
#[derive(Debug)]
pub struct VerificationResult {
    /// Packets that were successfully verified
    pub verified_packets: Vec<LayerZeroPacketInfo>,
    /// Packets that failed verification with error details
    pub failed_packets: Vec<(LayerZeroPacketInfo, String)>,
}

/// Represents a chain's monitoring context
#[derive(Debug)]
pub struct ChainMonitor {
    /// Chain ID for this monitor
    pub chain_id: u64,
    /// LayerZero endpoint address on this chain
    pub endpoint_address: Address,
    /// Event subscription stream (None if WebSocket unavailable)
    pub stream: alloy::pubsub::Subscription<Log>,
    /// Packets to monitor on this chain
    pub packets: Vec<LayerZeroPacketInfo>,
}

impl ChainMonitor {
    /// Monitors the WebSocket event stream for packet verification events.
    ///
    /// This method subscribes to `PayloadVerified` events on a destination chain and tracks
    /// when specific packets are verified and the ReceiveLib reports them as verifiable.
    ///
    /// ## Returns
    ///
    /// Returns a vector of GUIDs for packets that were verified during monitoring.
    async fn monitor_packet_stream(
        mut self,
        deadline: Instant,
        chain_configs: LZChainConfigs,
    ) -> Result<Vec<B256>, SettlementError> {
        // Create lookup map using header hash as key
        let packet_lookup: HashMap<B256, LayerZeroPacketInfo> = self
            .packets
            .iter()
            .map(|packet| {
                info!(
                    guid = ?packet.guid,
                    nonce = packet.nonce,
                    receiver = ?packet.receiver,
                    header_hash = ?packet.header_hash,
                    "Prepared packet for monitoring"
                );
                (packet.header_hash, packet.clone())
            })
            .collect();

        let mut verified_guids = Vec::with_capacity(self.packets.len());
        let mut remaining = self.packets.len();

        info!(
            endpoint = ?self.endpoint_address,
            num_packets = self.packets.len(),
            timeout_secs = (deadline - Instant::now()).as_secs(),
            "Starting PacketVerified event monitoring"
        );

        while remaining > 0 {
            tokio::select! {
                result = self.stream.recv() => {
                    match result {
                        Ok(log) => {
                            info!(
                                log_address = ?log.inner.address,
                                "Received log event"
                            );

                            match IReceiveUln302::PayloadVerified::decode_log(&log.inner) {
                                Ok(event) => {
                                    info!(
                                        dvn = ?event.dvn,
                                        header_len = event.header.len(),
                                        confirmations = ?event.confirmations,
                                        proof_hash = ?event.proofHash,
                                        "Decoded PayloadVerified event"
                                    );

                                    if let Some(packet) = packet_lookup.get(&keccak256(&event.header)) {
                                        // Each DVN will emit its own PayloadVerified log, and only when we meet the configured threshold does the following call return true.
                                        match chain_configs.is_message_available(packet).await {
                                            Ok(true) => {
                                                verified_guids.push(packet.guid);
                                                remaining -= 1;
                                                info!(
                                                    guid = ?packet.guid,
                                                    nonce = packet.nonce,
                                                    receiver = ?packet.receiver,
                                                    remaining,
                                                    "Message verified and ready"
                                                );
                                            }
                                            Ok(false) => {
                                                info!(
                                                    guid = ?packet.guid,
                                                    "Message not yet ready"
                                                );
                                            }
                                            Err(e) => {
                                                warn!(
                                                    guid = ?packet.guid,
                                                    error = ?e,
                                                    "Failed to check message availability"
                                                );
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!(
                                        error = ?e,
                                        "Failed to decode PayloadVerified event"
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
}

/// Result of initial verification status check
#[derive(Debug)]
pub struct InitialVerificationStatus {
    /// Packets that still need verification, grouped by destination chain
    pub pending_by_chain: HashMap<u64, Vec<LayerZeroPacketInfo>>,
    /// GUIDs of packets that were already verified
    pub already_verified_guids: Vec<B256>,
}

/// Handles monitoring for LayerZero verification messages
#[derive(Debug)]
pub(super) struct LayerZeroVerificationMonitor {
    chain_configs: LZChainConfigs,
}

impl LayerZeroVerificationMonitor {
    /// Creates a new LayerZero verification monitor
    pub(super) fn new(chain_configs: LZChainConfigs) -> Self {
        Self { chain_configs }
    }

    /// Waits for LayerZero messages to be verified
    pub async fn wait_for_verifications(
        &self,
        packets: Vec<LayerZeroPacketInfo>,
        timeout_seconds: u64,
    ) -> Result<VerificationResult, SettlementError> {
        if packets.is_empty() {
            return Ok(VerificationResult { verified_packets: vec![], failed_packets: vec![] });
        }

        // todo(joshiedo): deadline should be actually be "refundTimestamp - N minutes"
        let deadline = Instant::now() + Duration::from_secs(timeout_seconds);

        info!(
            num_packets = packets.len(),
            timeout_secs = timeout_seconds,
            "Waiting for LayerZero message verifications"
        );

        let packets_by_chain = self.group_packets_by_chain(packets.clone());
        let chain_monitors = self.setup_chain_monitors(packets_by_chain).await?;
        let initial_status = self.check_initial_verification_status(&chain_monitors).await?;

        if initial_status.pending_by_chain.is_empty() {
            info!("All {} messages already verified", initial_status.already_verified_guids.len());
            return Ok(VerificationResult { verified_packets: packets, failed_packets: vec![] });
        }

        let verified_via_events = self
            .monitor_pending_messages(&initial_status.pending_by_chain, chain_monitors, deadline)
            .await?;

        // Combine pre-verified GUIDs with those verified via events
        let mut all_verified_guids = initial_status.already_verified_guids;
        all_verified_guids.extend(verified_via_events);

        let final_result = self
            .final_verification_check(
                all_verified_guids,
                &initial_status.pending_by_chain,
                &packets,
            )
            .await?;

        Ok(final_result)
    }

    /// Groups packets by their destination chain.
    pub fn group_packets_by_chain(
        &self,
        packets: Vec<LayerZeroPacketInfo>,
    ) -> HashMap<u64, Vec<LayerZeroPacketInfo>> {
        // Use fold for a more functional approach that can be slightly more efficient
        packets.into_iter().fold(HashMap::default(), |mut map, packet| {
            map.entry(packet.dst_chain_id).or_default().push(packet);
            map
        })
    }

    /// Sets up event monitors for tracking packet verification events across all chains.
    pub async fn setup_chain_monitors(
        &self,
        packets_by_chain: HashMap<u64, Vec<LayerZeroPacketInfo>>,
    ) -> Result<Vec<ChainMonitor>, SettlementError> {
        let subscription_tasks: Vec<_> = packets_by_chain
            .into_iter()
            .map(|(chain_id, packets)| {
                let chain_configs = self.chain_configs.clone();

                tokio::spawn(async move {
                    let config = chain_configs.ensure_chain_config(chain_id)?;

                    // Get the receive library address for monitoring PayloadVerified events
                    let first_packet = packets.first().ok_or_else(|| {
                        SettlementError::InternalError("No packets for chain".to_string())
                    })?;

                    let filter = Filter::new()
                        .address(first_packet.receive_lib_address)
                        .event_signature(IReceiveUln302::PayloadVerified::SIGNATURE_HASH);

                    Ok::<_, SettlementError>(ChainMonitor {
                        chain_id,
                        endpoint_address: config.endpoint_address,
                        stream: config.provider.subscribe_logs(&filter).await?,
                        packets,
                    })
                })
            })
            .collect();

        // Collect all monitors
        let mut monitors = Vec::with_capacity(subscription_tasks.len());
        for task in subscription_tasks {
            match task.await {
                Ok(Ok(monitor)) => monitors.push(monitor),
                Ok(Err(e)) => return Err(e),
                Err(e) => {
                    return Err(SettlementError::InternalError(e.to_string()));
                }
            }
        }

        info!(num_chains = monitors.len(), "Event monitors established for chains");

        Ok(monitors)
    }

    /// Checks the initial verification status of all monitored packets.
    ///
    /// This method performs an initial sweep to determine which messages are already
    /// verified before starting active monitoring. This optimization prevents unnecessary
    /// waiting for messages that are already available.
    /// ## Returns
    ///
    /// Returns an `InitialVerificationStatus` struct containing:
    /// - `already_verified_guids`: GUIDs of messages that were already verified
    /// - `pending_by_chain`: HashMap of chain ID to packets that still need verification
    pub async fn check_initial_verification_status(
        &self,
        monitors: &[ChainMonitor],
    ) -> Result<InitialVerificationStatus, SettlementError> {
        let mut pending_by_chain: HashMap<u64, Vec<LayerZeroPacketInfo>> = HashMap::default();
        let mut already_verified_guids = Vec::new();

        for monitor in monitors {
            let mut pending = Vec::with_capacity(monitor.packets.len());
            for packet in &monitor.packets {
                if !self.chain_configs.is_message_available(packet).await? {
                    pending.push(packet.clone());
                } else {
                    already_verified_guids.push(packet.guid);
                }
            }

            info!(
                chain_id = monitor.chain_id,
                total_packets = monitor.packets.len(),
                pending_packets = pending.len(),
                already_verified = monitor.packets.len() - pending.len(),
                "Initial verification status"
            );

            if !pending.is_empty() {
                pending_by_chain.insert(monitor.chain_id, pending);
            }
        }

        Ok(InitialVerificationStatus { pending_by_chain, already_verified_guids })
    }

    /// Monitors pending messages across all chains until the specified deadline.
    ///
    /// This method coordinates parallel monitoring of multiple chains, using event
    /// subscriptions where available and falling back to deadline-based waiting otherwise.
    ///
    /// ## Arguments
    ///
    /// * `pending_by_chain` - Map of chain IDs to packets that need verification
    /// * `monitors` - Chain monitors with potential event subscriptions
    /// * `deadline` - Absolute time to stop monitoring
    ///
    /// ## Returns
    ///
    /// Returns a vector of GUIDs for all packets that were verified during monitoring.
    ///
    /// ## Monitoring Strategy
    ///
    /// - **With WebSocket**: Actively monitors `PacketVerified` events in real-time
    /// - **Without WebSocket**: Waits until deadline then performs final status check
    /// - **Parallel execution**: All chains are monitored concurrently for efficiency
    ///
    /// ## Error Handling
    ///
    /// Individual chain monitoring failures are logged but don't fail the overall
    /// operation, ensuring resilience in multi-chain scenarios.
    pub async fn monitor_pending_messages(
        &self,
        pending_by_chain: &HashMap<ChainId, Vec<LayerZeroPacketInfo>>,
        monitors: Vec<ChainMonitor>,
        deadline: Instant,
    ) -> Result<Vec<B256>, SettlementError> {
        let mut monitoring_tasks = Vec::with_capacity(pending_by_chain.len());

        for monitor in monitors {
            if let Some(pending_packets) = pending_by_chain.get(&monitor.chain_id) {
                if pending_packets.is_empty() {
                    continue;
                }

                let chain_configs = self.chain_configs.clone();
                let task = tokio::spawn(async move {
                    monitor.monitor_packet_stream(deadline, chain_configs).await
                });
                monitoring_tasks.push(task);
            }
        }

        // Collect results from all monitoring tasks
        let mut all_verified_guids = Vec::with_capacity(monitoring_tasks.len());
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

    /// Performs a final verification check for any messages not caught by event monitoring.
    ///
    /// This method serves as a safety net to catch messages that may have been verified
    /// after event monitoring stopped, in cases where event subscriptions failed or any edge cases
    /// where events were missed.
    pub async fn final_verification_check(
        &self,
        verified_guids: Vec<B256>,
        pending_by_chain: &HashMap<u64, Vec<LayerZeroPacketInfo>>,
        all_packets: &[LayerZeroPacketInfo],
    ) -> Result<VerificationResult, SettlementError> {
        let total_pending: usize = pending_by_chain.values().map(|v| v.len()).sum();
        let verified_via_events = verified_guids.len();

        // Build set of verified GUIDs for quick lookup
        let mut verified_guid_set: HashMap<B256, ()> =
            verified_guids.into_iter().map(|g| (g, ())).collect();

        // If we haven't verified everything via events, check remaining
        if verified_via_events < total_pending {
            info!(
                verified_via_events,
                total_pending, "Timeout reached, performing final verification check"
            );

            // Check remaining unverified packets
            let remaining_checks = try_join_all(
                pending_by_chain
                    .values()
                    .flat_map(|packets| packets.iter())
                    .filter(|packet| !verified_guid_set.contains_key(&packet.guid))
                    .map(|packet| async move {
                        self.chain_configs
                            .is_message_available(packet)
                            .await
                            .map(|is_verified| (packet.clone(), is_verified))
                    }),
            )
            .await?;

            // Add newly verified packets to the set
            for (packet, is_verified) in remaining_checks {
                if is_verified {
                    verified_guid_set.insert(packet.guid, ());
                }
            }
        }

        // Build final result by categorizing all packets
        let mut verified_packets = Vec::new();
        let mut failed_packets = Vec::new();

        for packet in all_packets {
            if verified_guid_set.contains_key(&packet.guid) {
                verified_packets.push(packet.clone());
            } else {
                let error_msg = format!(
                    "Message verification timeout: GUID {}, src_chain {}, dst_chain {}",
                    packet.guid, packet.src_chain_id, packet.dst_chain_id
                );
                failed_packets.push((packet.clone(), error_msg));
            }
        }

        if !failed_packets.is_empty() {
            warn!(
                "Failed to verify {} out of {} messages",
                failed_packets.len(),
                all_packets.len()
            );
        }

        Ok(VerificationResult { verified_packets, failed_packets })
    }
}
