//! # LayerZero Verification Monitoring
//!
//! This module provides utilities for monitoring LayerZero message verifications.
//! It maintains a single subscription per destination chain to minimize connections while serving
//! multiple concurrent verification requests through broadcast channels.
//!
//! ## Architecture
//!
//! The monitor optimizes resource usage by:
//!
//! 1. Creating one WebSocket subscription per destination chain (not per packet)
//! 2. Broadcasting `PayloadVerified` events to all interested receivers via channels
//! 3. Automatically cleaning up unused subscriptions when no receivers remain
//! 4. Checking initial verification status to avoid unnecessary subscriptions

use super::{
    contracts::{ILayerZeroEndpointV2, IReceiveUln302},
    types::EndpointId,
};
use crate::{
    interop::settler::{SettlementError, layerzero::types::LayerZeroPacketInfo},
    types::LZChainConfigs,
};
use alloy::{
    primitives::{B256, ChainId, keccak256, map::HashMap},
    providers::Provider,
    pubsub::Subscription,
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use futures_util::future::try_join_all;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    sync::{RwLock, broadcast},
    time::{Duration, Instant, sleep_until},
};
use tracing::{info, warn};

/// Represents an active subscription for a specific chain.
#[derive(Debug)]
struct ChainSubscription {
    /// Broadcasts decoded PayloadVerified events to all consumers
    event_sender: broadcast::Sender<IReceiveUln302::PayloadVerified>,
    /// Number of active consumers to this subscription.
    subscribers_count: Arc<AtomicUsize>,
}

impl ChainSubscription {
    /// Spawns a new chain log subscription.
    ///
    /// Only one per chain should be spawned.
    fn spawn(chain_id: ChainId, mut stream: Subscription<Log>) -> Self {
        let (tx, _rx) = broadcast::channel(10000);

        // Spawn background task to process the stream
        let event_sender = tx.clone();
        tokio::spawn(async move {
            loop {
                let Ok(log) = stream.recv().await else {
                    warn!(chain_id, "Stream error - subscription ended");
                    break;
                };

                if let Ok(decoded) = IReceiveUln302::PayloadVerified::decode_log(&log.inner) {
                    let _ = tx.send(decoded.data);
                }
            }
            info!(chain_id, "Stream processing ended");
        });

        Self { event_sender, subscribers_count: Arc::new(AtomicUsize::new(0)) }
    }

    /// Generates a new InternalSubscription.
    fn subscribe(&self) -> InternalSubscription {
        self.subscribers_count.fetch_add(1, Ordering::Relaxed);
        InternalSubscription {
            inner: self.event_sender.subscribe(),
            chain_subscription_counter: self.subscribers_count.clone(),
        }
    }
}

/// LayerZero verification monitor that maintains one subscription per destination chain and
/// broadcasts events to all interested consumers.
#[derive(Debug)]
pub struct LayerZeroVerificationMonitor {
    /// One subscription per destination chain
    log_subscriptions: RwLock<HashMap<ChainId, ChainSubscription>>,
    /// Chain configurations for accessing providers and endpoints
    chain_configs: LZChainConfigs,
}

impl LayerZeroVerificationMonitor {
    /// Creates a new LayerZero verification monitor with the given chain configurations.
    pub fn new(chain_configs: LZChainConfigs) -> Self {
        Self { log_subscriptions: RwLock::new(HashMap::default()), chain_configs }
    }

    /// Waits for LayerZero packets to be verified on their destination chains.
    pub async fn wait_for_verifications(
        &self,
        packets: Vec<LayerZeroPacketInfo>,
        timeout_seconds: u64,
    ) -> Result<VerificationResult, SettlementError> {
        if packets.is_empty() {
            return Ok(VerificationResult { verified_packets: vec![], failed_packets: vec![] });
        }

        // todo(joshiedo): deadline should be actually be "refundTimestamp - N minutes"
        let timeout_deadline = Instant::now() + Duration::from_secs(timeout_seconds);

        info!(
            num_packets = packets.len(),
            timeout_secs = timeout_seconds,
            "Waiting for LayerZero message verifications"
        );

        // Only subscribe to events for packets that aren't already verified
        let status = self.check_initial_verification_status(&packets).await?;

        // If everything is already verified, no need to subscribe to events
        if status.pending.is_empty() {
            info!("All {} messages already verified", status.already_verified_guids.len());
            return Ok(VerificationResult { verified_packets: packets, failed_packets: vec![] });
        }

        let verified_via_events = self.monitor_packets(status.pending, timeout_deadline).await?;

        // Combine pre-verified GUIDs with those verified via events
        let mut all_verified_guids = status.already_verified_guids;
        all_verified_guids.extend(verified_via_events);

        final_verification_check(all_verified_guids, &packets).await
    }

    /// Checks which packets are already verified on-chain.
    async fn check_initial_verification_status(
        &self,
        packets: &[LayerZeroPacketInfo],
    ) -> Result<InitialVerificationStatus, SettlementError> {
        let availability_checks = packets.iter().map(async |packet| {
            let is_available = self.chain_configs.is_message_available(packet).await?;
            Ok::<_, SettlementError>((packet.clone(), is_available))
        });

        let results = try_join_all(availability_checks).await?;

        let mut pending = Vec::new();
        let mut already_verified_guids = Vec::new();

        for (packet, is_available) in results {
            if is_available {
                already_verified_guids.push(packet.guid);
            } else {
                pending.push(packet);
            }
        }

        info!(
            total_packets = packets.len(),
            pending_packets = pending.len(),
            already_verified = already_verified_guids.len(),
            "Initial verification status"
        );

        Ok(InitialVerificationStatus { pending, already_verified_guids })
    }

    /// Monitors pending packets for verification events on their destination chains.
    ///
    /// Returns GUIDs of packets that were verified before the timeout.
    async fn monitor_packets(
        &self,
        pending_packets: Vec<LayerZeroPacketInfo>,
        timeout_deadline: Instant,
    ) -> Result<Vec<B256>, SettlementError> {
        if pending_packets.is_empty() {
            return Ok(Vec::new());
        }

        let monitoring_futures = pending_packets.into_iter().map(async |packet| {
            let Some((_, config)) = self
                .chain_configs
                .iter()
                .find(|(other_chain_id, _)| **other_chain_id != packet.dst_chain_id)
            else {
                // should not happen, it would have been caught by the preflight diagnostics.
                return Err(SettlementError::InternalError("No source endpoint found".to_string()));
            };

            let mut rx = self.subscribe_to_payload_events(packet.dst_chain_id, config.endpoint_id).await?;

            let result = loop {
                tokio::select! {
                    Ok(event) = rx.recv() => {
                        // check if this event is for our packet
                        if keccak256(&event.header) == packet.header_hash
                            && self.chain_configs.is_message_available(&packet).await.unwrap_or(false) {
                                info!(
                                    ?packet.guid,
                                    "Packet verified on chain"
                                );
                                break Some(packet.guid);
                            }
                    }
                    _ = sleep_until(timeout_deadline) => {
                        break None;
                    }
                }
            };

            // Check if we're the last receiver before dropping
            let was_last = rx.chain_subscription_counter.load(Ordering::Acquire) == 1;
            drop(rx);

            // Only try to clean up if we were the last receiver
            if was_last {
                self.cleanup_chain_if_unused(packet.dst_chain_id).await;
            }

            Ok(result)
        });

        Ok(try_join_all(monitoring_futures).await?.into_iter().flatten().collect())
    }

    /// Subscribes to PayloadVerified events on the specified chain.
    ///
    /// If a subscription already exists for the chain, returns a new receiver for the existing
    /// broadcast channel. Otherwise, creates a new subscription and returns a receiver for it.
    pub async fn subscribe_to_payload_events(
        &self,
        chain_id: ChainId,
        src_endpoint_id: EndpointId,
    ) -> Result<InternalSubscription, SettlementError> {
        // check if subscription already exists for this chain
        let subs = self.log_subscriptions.read().await;
        if let Some(sub) = subs.get(&chain_id) {
            return Ok(sub.subscribe());
        }

        // create subscription
        let mut subs = self.log_subscriptions.write().await;

        // double-check - another task may have created it while we waited for write lock
        if let Some(sub) = subs.get(&chain_id) {
            return Ok(sub.subscribe());
        }

        let Some(config) = self.chain_configs.get(&chain_id) else {
            // should have been caught by the preflight diagnostics
            return Err(SettlementError::UnsupportedChain(chain_id));
        };

        // get the receive library address
        let endpoint = ILayerZeroEndpointV2::new(config.endpoint_address, &config.provider);
        let receive_lib_result =
            endpoint.getReceiveLibrary(config.settler_address, src_endpoint_id).call().await?;
        let receive_lib_address = receive_lib_result.lib;

        // subscribe to events emitted by the library
        let stream = config
            .provider
            .subscribe_logs(
                &Filter::new()
                    .address(receive_lib_address)
                    .event_signature(IReceiveUln302::PayloadVerified::SIGNATURE_HASH),
            )
            .await?;

        // spawn the chain subscription
        let subscription = ChainSubscription::spawn(chain_id, stream);
        let rx = subscription.subscribe();
        subs.insert(chain_id, subscription);

        info!(
            chain_id,
            receive_lib_address = ?receive_lib_address,
            "Created global subscription for chain"
        );

        Ok(rx)
    }

    /// Removes a specific chain subscription if it has no active receivers.
    async fn cleanup_chain_if_unused(&self, chain_id: ChainId) {
        let mut subs = self.log_subscriptions.write().await;
        if let Some(subscription) = subs.get(&chain_id)
            && subscription.subscribers_count.load(Ordering::Relaxed) == 0
        {
            subs.remove(&chain_id);
            info!(chain_id, "Removed unused chain subscription");
        }
    }
}

/// Result of verification monitoring for LayerZero messages
#[derive(Debug)]
pub struct VerificationResult {
    /// Packets that were successfully verified
    pub verified_packets: Vec<LayerZeroPacketInfo>,
    /// Packets that failed verification with error details
    pub failed_packets: Vec<(LayerZeroPacketInfo, String)>,
}

/// Result of initial verification status check.
#[derive(Debug)]
struct InitialVerificationStatus {
    /// Packets that still need verification
    pending: Vec<LayerZeroPacketInfo>,
    /// GUIDs of packets that are already verified
    already_verified_guids: Vec<B256>,
}

/// Handle to a chain's event stream that automatically tracks active receivers.
///
/// When dropped, decrements the subscriber count for its chain subscription.
#[derive(Debug)]
pub struct InternalSubscription {
    /// The underlying broadcast receiver for PayloadVerified events
    inner: broadcast::Receiver<IReceiveUln302::PayloadVerified>,
    /// Shared counter tracking total subscribers for this chain's subscription
    chain_subscription_counter: Arc<AtomicUsize>,
}

impl InternalSubscription {
    async fn recv(
        &mut self,
    ) -> Result<IReceiveUln302::PayloadVerified, broadcast::error::RecvError> {
        self.inner.recv().await
    }
}

impl Drop for InternalSubscription {
    fn drop(&mut self) {
        self.chain_subscription_counter.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Helper function for final verification check
async fn final_verification_check(
    verified_guids: Vec<B256>,
    all_packets: &[LayerZeroPacketInfo],
) -> Result<VerificationResult, SettlementError> {
    // Build set of verified GUIDs for quick lookup
    let verified_guid_set: HashMap<B256, ()> =
        verified_guids.into_iter().map(|g| (g, ())).collect();

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
        warn!("Failed to verify {} out of {} messages", failed_packets.len(), all_packets.len());
    }

    Ok(VerificationResult { verified_packets, failed_packets })
}
