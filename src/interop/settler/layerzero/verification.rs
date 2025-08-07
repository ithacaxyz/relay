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

use super::contracts::{ILayerZeroEndpointV2, IReceiveUln302};
use crate::{
    interop::settler::{SettlementError, layerzero::types::LayerZeroPacketInfo},
    types::LZChainConfigs,
};
use alloy::{
    primitives::{
        B256, ChainId, keccak256,
        map::{HashMap, HashSet},
    },
    providers::Provider,
    pubsub::Subscription,
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use futures_util::future::try_join_all;
use itertools::{Either, Itertools};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    sync::{RwLock, broadcast, mpsc},
    time::{Duration, Instant, sleep_until},
};
use tracing::{debug, info, warn};

/// Represents an active subscription for a specific chain.
struct ChainSubscription {
    /// Broadcasts decoded PayloadVerified events to all consumers
    event_sender: broadcast::Sender<IReceiveUln302::PayloadVerified>,
    /// Handle for cleanup requests and subscriber tracking
    handle: ChainSubscriptionHandle,
}

impl std::fmt::Debug for ChainSubscription {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainSubscription")
            .field("subscribers_count", &self.handle.subscribers_count.load(Ordering::Relaxed))
            .finish()
    }
}

impl ChainSubscription {
    /// Spawns a new chain log subscription.
    ///
    /// Only one per chain should be spawned.
    fn spawn(
        chain_id: ChainId,
        mut stream: Subscription<Log>,
        monitor: LayerZeroVerificationMonitor,
    ) -> Self {
        let (tx, _rx) = broadcast::channel(10000);
        let subscribers_count = Arc::new(AtomicUsize::new(0));
        let (cleanup_tx, mut cleanup_rx) = mpsc::unbounded_channel();

        // Create the cleanup handle
        let handle =
            ChainSubscriptionHandle { cleanup_tx, subscribers_count: subscribers_count.clone() };

        // Spawn background task to process the stream and handle cleanup
        let event_sender = tx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // Process stream events
                    result = stream.recv() => {
                        let Ok(log) = result else {
                            warn!(chain_id, "Stream error - subscription ended");
                            break;
                        };

                        if let Ok(decoded) = IReceiveUln302::PayloadVerified::decode_log(&log.inner) {
                            let _ = tx.send(decoded.data);
                        }
                    }
                    // Handle cleanup requests
                    Some(()) = cleanup_rx.recv() => {
                        if monitor.try_cleanup(chain_id).await {
                            debug!(chain_id, "Cleanup successful, terminating stream task");
                            break;
                        }
                    }
                }
            }
            info!(chain_id, "Stream processing ended");
        });

        Self { event_sender, handle }
    }

    /// Generates a new InternalSubscription.
    fn subscribe(&self, packet: LayerZeroPacketInfo) -> InternalSubscription {
        self.handle.subscribers_count.fetch_add(1, Ordering::Relaxed);
        InternalSubscription {
            packet,
            inner: self.event_sender.subscribe(),
            chain_handle: self.handle.clone(),
        }
    }
}

/// Handle for requesting cleanup of a chain subscription and track subscribers.
#[derive(Clone, Debug)]
struct ChainSubscriptionHandle {
    /// Channel to request cleanup
    cleanup_tx: mpsc::UnboundedSender<()>,
    /// Shared counter tracking total subscribers
    subscribers_count: Arc<AtomicUsize>,
}

impl ChainSubscriptionHandle {
    /// Notify that a subscriber is being dropped
    fn notify_drop(&self) {
        let prev = self.subscribers_count.fetch_sub(1, Ordering::Relaxed);

        // If we were the last subscriber, request cleanup
        if prev == 1 {
            // Send cleanup request - ignore error if receiver is gone (shutting down)
            let _ = self.cleanup_tx.send(());
        }
    }
}

/// Inner state for the verification monitor.
#[derive(Debug)]
struct LayerZeroVerificationMonitorInner {
    /// One node subscription per destination chain
    log_subscriptions: RwLock<HashMap<ChainId, ChainSubscription>>,
    /// Chain configurations for accessing providers and endpoints
    chain_configs: LZChainConfigs,
}

/// LayerZero verification monitor that maintains one subscription per destination chain and
/// broadcasts events to all interested consumers.
#[derive(Debug, Clone)]
pub struct LayerZeroVerificationMonitor {
    inner: Arc<LayerZeroVerificationMonitorInner>,
}

impl LayerZeroVerificationMonitor {
    /// Creates a new LayerZero verification monitor with the given chain configurations.
    pub fn new(chain_configs: LZChainConfigs) -> Self {
        Self {
            inner: Arc::new(LayerZeroVerificationMonitorInner {
                log_subscriptions: RwLock::new(HashMap::default()),
                chain_configs,
            }),
        }
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

        // create subscriptions for all destination chains
        let packet_subscriptions = try_join_all(
            packets.iter().map(async |packet| self.subscribe_to_payload_events(packet).await),
        )
        .await?;

        // check initial verification status which will come only with the pending packet
        // subscriptions
        let status = self.check_initial_verification_status(packet_subscriptions).await?;

        // if everything is already verified, return immediately
        if status.pending.is_empty() {
            info!("All {} messages already verified", status.already_verified_guids.len());
            return Ok(VerificationResult { verified_packets: packets, failed_packets: vec![] });
        }

        // monitor pending packets with their subscriptions
        let verified_via_events = self.monitor_packets(status.pending, timeout_deadline).await?;

        // Combine pre-verified GUIDs with those verified via events
        final_verification_check(
            status.already_verified_guids.into_iter().chain(verified_via_events),
            &packets,
        )
    }

    /// Checks which packets are already verified on-chain.
    ///
    /// Returns pending packet subscriptions and GUIDs of already verified packets.
    async fn check_initial_verification_status(
        &self,
        packet_subscriptions: Vec<InternalSubscription>,
    ) -> Result<InitialVerificationStatus, SettlementError> {
        let total_packets = packet_subscriptions.len();

        // Check availability for all packets in parallel and partition results
        let (already_verified_guids, pending): (Vec<_>, Vec<_>) =
            try_join_all(packet_subscriptions.into_iter().map(async |rx| {
                if self.inner.chain_configs.is_message_available(&rx.packet).await? {
                    Ok::<_, SettlementError>(Either::Left(rx.packet.guid))
                } else {
                    // Packet still pending - keep subscription
                    Ok(Either::Right(rx))
                }
            }))
            .await?
            .into_iter()
            .partition_map(|result| result);

        info!(
            total_packets,
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
        pending_subscriptions: Vec<InternalSubscription>,
        timeout_deadline: Instant,
    ) -> Result<Vec<B256>, SettlementError> {
        if pending_subscriptions.is_empty() {
            return Ok(Vec::new());
        }

        let monitoring_futures = pending_subscriptions.into_iter().map(async |mut rx| {
            let result = loop {
                tokio::select! {
                    Ok(event) = rx.recv() => {
                        // check if this event is for our packet
                        if keccak256(&event.header) == rx.packet.header_hash
                            && self.inner.chain_configs.is_message_available(&rx.packet).await.unwrap_or(false) {
                                info!(
                                    guid = ?rx.packet.guid,
                                    "Packet verified on chain"
                                );
                                break Some(rx.packet.guid);
                        }
                    }
                    _ = sleep_until(timeout_deadline) => {
                        break None;
                    }
                }
            };

            Ok::<_, SettlementError>(result)
        });

        Ok(try_join_all(monitoring_futures).await?.into_iter().flatten().collect())
    }

    /// Subscribes to PayloadVerified events for the specified packet.
    ///
    /// If a subscription already exists for the chain, returns a new receiver for the existing
    /// broadcast channel. Otherwise, creates a new subscription and returns a receiver for it.
    pub async fn subscribe_to_payload_events(
        &self,
        packet: &LayerZeroPacketInfo,
    ) -> Result<InternalSubscription, SettlementError> {
        // Find the source endpoint ID from the source chain config
        let Some((_src_chain_id, src_config)) =
            self.inner.chain_configs.iter().find(|(id, _)| **id == packet.src_chain_id)
        else {
            return Err(SettlementError::InternalError(format!(
                "No config found for source chain {}",
                packet.src_chain_id
            )));
        };
        let src_endpoint_id = src_config.endpoint_id;

        // check if node subscription already exists for this chain
        {
            let subs = self.inner.log_subscriptions.read().await;
            if let Some(sub) = subs.get(&packet.dst_chain_id) {
                return Ok(sub.subscribe(packet.clone()));
            }
        } // Drop read lock here

        // create node subscription
        let mut subs = self.inner.log_subscriptions.write().await;

        // double-check - another task may have created it while we waited for write lock
        if let Some(sub) = subs.get(&packet.dst_chain_id) {
            return Ok(sub.subscribe(packet.clone()));
        }

        let Some(config) = self.inner.chain_configs.get(&packet.dst_chain_id) else {
            // should have been caught by the preflight diagnostics
            return Err(SettlementError::UnsupportedChain(packet.dst_chain_id));
        };

        // get the receive library address
        let endpoint = ILayerZeroEndpointV2::new(config.endpoint_address, &config.provider);
        let receive_lib_result =
            endpoint.getReceiveLibrary(config.settler_address, src_endpoint_id).call().await?;

        // subscribe to events emitted by the library
        let stream = config
            .provider
            .subscribe_logs(
                &Filter::new()
                    .address(receive_lib_result.lib)
                    .event_signature(IReceiveUln302::PayloadVerified::SIGNATURE_HASH),
            )
            .await?;

        // spawn the chain subscription
        let subscription = ChainSubscription::spawn(packet.dst_chain_id, stream, self.clone());
        let rx = subscription.subscribe(packet.clone());
        subs.insert(packet.dst_chain_id, subscription);

        info!(
            chain_id = packet.dst_chain_id,
            receive_lib_address = ?receive_lib_result.lib,
            "Created global subscription for chain"
        );

        Ok(rx)
    }

    /// Try to cleanup a chain subscription if it has no active receivers.
    ///
    /// Returns true if the subscription was removed, false otherwise.
    async fn try_cleanup(&self, chain_id: ChainId) -> bool {
        let mut subs = self.inner.log_subscriptions.write().await;
        if let Some(subscription) = subs.get(&chain_id) {
            // double-check that there are truly no subscribers
            if subscription.handle.subscribers_count.load(Ordering::Relaxed) == 0 {
                subs.remove(&chain_id);
                info!(chain_id, "Removed unused chain subscription");
                return true;
            }
        }
        false
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
struct InitialVerificationStatus {
    /// Subscriptions for packets that still need verification
    pending: Vec<InternalSubscription>,
    /// GUIDs of packets that are already verified
    already_verified_guids: Vec<B256>,
}

/// Handle to a chain's event stream that automatically tracks active receivers.
///
/// When dropped, decrements the subscriber count for its chain subscription.
#[derive(Debug)]
pub struct InternalSubscription {
    /// The packet being monitored
    packet: LayerZeroPacketInfo,
    /// The underlying broadcast receiver for PayloadVerified events
    inner: broadcast::Receiver<IReceiveUln302::PayloadVerified>,
    /// Handle for cleanup when dropped
    chain_handle: ChainSubscriptionHandle,
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
        self.chain_handle.notify_drop();
    }
}

/// Helper function for final verification check
fn final_verification_check(
    verified_guids: impl IntoIterator<Item = B256>,
    all_packets: &[LayerZeroPacketInfo],
) -> Result<VerificationResult, SettlementError> {
    // Build set of verified GUIDs for quick lookup
    let verified_guid_set: HashSet<B256> = verified_guids.into_iter().collect();

    // Build final result by categorizing all packets using partition_map
    let (verified_packets, failed_packets): (Vec<_>, Vec<_>) =
        all_packets.iter().partition_map(|packet| {
            if verified_guid_set.contains(&packet.guid) {
                Either::Left(packet.clone())
            } else {
                let error_msg = format!(
                    "Message verification timeout: GUID {}, src_chain {}, dst_chain {}",
                    packet.guid, packet.src_chain_id, packet.dst_chain_id
                );
                Either::Right((packet.clone(), error_msg))
            }
        });

    if !failed_packets.is_empty() {
        warn!("Failed to verify {} out of {} messages", failed_packets.len(), all_packets.len());
    }

    Ok(VerificationResult { verified_packets, failed_packets })
}
