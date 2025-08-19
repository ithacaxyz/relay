//! # LayerZero Verification Monitoring
//!
//! This module provides utilities for monitoring LayerZero message verifications.
//! It maintains one subscription per (destination chain, receive library) combination to minimize
//! connections while serving multiple concurrent verification requests through broadcast channels.
//!
//! Different settler addresses on the same chain may use different receive libraries, so we need
//! to monitor the specific receive library that will process each packet.

use crate::{
    interop::settler::{
        SettlementError,
        layerzero::{contracts::IReceiveUln302::PayloadVerified, types::LayerZeroPacketInfo},
    },
    types::LZChainConfigs,
};
use alloy::{
    primitives::{
        Address, B256, ChainId, keccak256,
        map::{HashMap, HashSet},
    },
    providers::Provider,
    pubsub::Subscription,
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use futures_util::future::join_all;
use itertools::{Either, Itertools};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::{
    sync::{RwLock, broadcast, mpsc},
    time::{Duration, Instant},
};
use tracing::{debug, error, info, trace, warn};

/// Represents an active log subscription for a specific chain and receive library combination.
///
/// Each subscription monitors PayloadVerified events from a specific receive library address
/// on a destination chain. Multiple packets can share the same subscription if they use the
/// same receive library.
#[derive(Debug)]
struct ChainSubscription {
    /// Broadcasts header hashes of `PayloadVerified` events to all consumers
    event_sender: broadcast::Sender<B256>,
    /// Handle for cleanup requests and subscriber tracking
    handle: ChainSubscriptionHandle,
}

impl ChainSubscription {
    /// Spawns a new chain log subscription.
    ///
    /// Only one subscription per chain and receive library combination should be spawned.
    fn spawn(
        key: SubscriptionKey,
        mut stream: Subscription<Log>,
        monitor: LayerZeroVerificationMonitor,
    ) -> Self {
        let (tx, _rx) = broadcast::channel(10000);
        let (cleanup_tx, mut cleanup_rx) = mpsc::unbounded_channel();

        let handle = ChainSubscriptionHandle {
            cleanup_tx,
            subscribers_count: Arc::new(AtomicUsize::new(0)),
        };
        let event_sender = tx.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = stream.recv() => {
                        let Ok(log) = result else {
                            warn!(chain_id = key.chain_id, receive_lib = ?key.receive_library, "Stream error - force removing subscription");
                            monitor.force_cleanup(key).await;
                            break;
                        };
                        let Ok(decoded) = PayloadVerified::decode_log(&log.inner) else {
                            continue;
                        };
                        let _ = tx.send(keccak256(&decoded.data.header));
                    }
                    // Handle cleanup request called by the last active PacketSubscription.
                    Some(()) = cleanup_rx.recv() => {
                        if monitor.try_cleanup(key).await {
                            debug!(chain_id = key.chain_id, receive_lib = ?key.receive_library, "Chain subscription cleaned up, terminating stream task");
                            break;
                        }
                    }
                }
            }
            info!(chain_id = key.chain_id, receive_lib = ?key.receive_library, "Stream processing ended");
        });

        Self { event_sender, handle }
    }

    /// Generates a new [`PacketSubscription`].
    fn subscribe(&self) -> PacketSubscription {
        self.handle.subscribers_count.fetch_add(1, Ordering::AcqRel);
        PacketSubscription {
            inner: self.event_sender.subscribe(),
            chain_handle: self.handle.clone(),
        }
    }
}

/// Handle for cleanup requests and subscriber tracking.
#[derive(Clone, Debug)]
struct ChainSubscriptionHandle {
    /// Channel to request cleanup
    cleanup_tx: mpsc::UnboundedSender<()>,
    /// Number of active consumers to this subscription.
    ///
    /// We track this so we only notify the ChainSubscription if we are the last listener.
    subscribers_count: Arc<AtomicUsize>,
}

impl ChainSubscriptionHandle {
    /// Notify that a subscriber is being dropped
    fn notify_drop(&self) {
        let prev = self.subscribers_count.fetch_sub(1, Ordering::AcqRel);

        // If we were the last subscriber, request cleanup
        if prev == 1 {
            let _ = self.cleanup_tx.send(());
        }
    }
}

/// Key for identifying unique subscriptions by chain and receive library
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct SubscriptionKey {
    /// The chain ID where the subscription is monitoring events
    chain_id: ChainId,
    /// The receive library address that emits PayloadVerified events
    receive_library: Address,
}

impl SubscriptionKey {
    fn new(chain_id: ChainId, receive_library: Address) -> Self {
        Self { chain_id, receive_library }
    }
}

/// Inner state for the verification monitor.
#[derive(Debug)]
struct LayerZeroVerificationMonitorInner {
    /// One node subscription per (chain, receive library) combination
    log_subscriptions: RwLock<HashMap<SubscriptionKey, ChainSubscription>>,
    /// Chain configurations for accessing providers and endpoints
    chain_configs: LZChainConfigs,
}

/// LayerZero verification monitor that maintains one subscription per (destination chain, receive
/// library) combination and broadcasts events to all interested consumers.
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
            "Starting LayerZero verification monitoring"
        );

        let verified_guids = self.monitor_packets(packets.clone(), timeout_deadline).await?;

        Ok(VerificationResult::new(verified_guids, &packets))
    }

    /// Monitors packets for verification events on their destination chains.
    ///
    /// Returns GUIDs of packets that were verified before the timeout.
    async fn monitor_packets(
        &self,
        packets: Vec<LayerZeroPacketInfo>,
        timeout_deadline: Instant,
    ) -> Result<Vec<B256>, SettlementError> {
        let results = join_all(
            packets.into_iter().map(|packet| self.monitor_packet(packet, timeout_deadline)),
        )
        .await;

        let mut packet_error = None;
        let mut verified_guids = Vec::new();

        for result in results {
            match result {
                Ok(guid) => verified_guids.push(guid),
                Err(SettlementError::Timeout(guid)) => {
                    error!(guid = ?guid, "Packet verification timed out");
                }
                Err(e) => {
                    error!(?e, "Packet monitoring error");
                    packet_error = Some(e);
                }
            }
        }

        // We only want to exit cleanly if we have verified all packets OR timed-out.
        if let Some(error) = packet_error {
            return Err(error);
        }

        Ok(verified_guids)
    }

    /// Monitor a single packet with retry logic for subscription failures.
    ///
    /// This function handles the complete lifecycle of monitoring a LayerZero packet:
    /// 1. Creates a subscription to the destination chain's PayloadVerified events
    /// 2. Checks if the packet is already verified on-chain (to avoid race conditions)
    /// 3. Waits for verification events, matching against the packet's header hash
    /// 4. Automatically recreates the subscription if the WebSocket connection drops
    ///
    /// The function ensures no events are missed by subscribing before checking chain state,
    /// and handles transient network failures by retrying.
    async fn monitor_packet(
        &self,
        packet: LayerZeroPacketInfo,
        timeout_deadline: Instant,
    ) -> Result<B256, SettlementError> {
        loop {
            let mut subscription = self.subscribe_to_payload_events(&packet).await?;

            // Check if already verified (after subscribing to avoid missing events)
            if self.inner.chain_configs.is_message_available(&packet).await? {
                debug!(guid = ?packet.guid, "Packet already verified on-chain");
                return Ok(packet.guid);
            }

            // Wait for event
            loop {
                tokio::select! {
                    result = subscription.inner.recv() => {
                        match result {
                            Ok(header_hash) => {
                                if header_hash == packet.header_hash {
                                    // PayloadVerified events are emitted for each DVN that verifies a packet. Multiple DVNs may need to verify before the message becomes executable. Rather than tracking DVN configurations, we check if the message is available for execution whenever we receive a verification.
                                    if self.inner.chain_configs.is_message_available(&packet).await? {
                                        trace!(
                                            guid = ?packet.guid,
                                            src_chain = packet.src_chain_id,
                                            dst_chain = packet.dst_chain_id,
                                            "Packet verified on chain"
                                        );
                                        return Ok(packet.guid);
                                    }
                                    trace!(guid = ?packet.guid, "Event received but not yet available");
                                }
                            }
                            Err(_) => {
                                // Channel closed - subscription died, break to recreate
                                warn!(guid = ?packet.guid, "Subscription closed, will recreate");
                                break;
                            }
                        }
                    }
                    _ = tokio::time::sleep_until(timeout_deadline) => {
                        warn!(
                            guid = ?packet.guid,
                            src_chain = packet.src_chain_id,
                            dst_chain = packet.dst_chain_id,
                            "Packet verification timed out"
                        );
                        return Err(SettlementError::Timeout(packet.guid));
                    }
                }
            }
        }
    }

    /// Subscribes to `PayloadVerified` events for the specified packet.
    ///
    /// If a subscription already exists for the (chain, receive library) combination, returns
    /// a new receiver for the existing broadcast channel. Otherwise, creates a new subscription
    /// for that specific receive library on the destination chain.
    ///
    /// The receive library address is taken from the packet info, which was determined when
    /// the packet was created based on the packet's receiver (settler) address.
    pub async fn subscribe_to_payload_events(
        &self,
        packet: &LayerZeroPacketInfo,
    ) -> Result<PacketSubscription, SettlementError> {
        // Create subscription key using the receive library address from the packet
        let key = SubscriptionKey::new(packet.dst_chain_id, packet.receive_lib_address);

        // check if node subscription already exists for this key
        {
            let subs = self.inner.log_subscriptions.read().await;
            if let Some(sub) = subs.get(&key) {
                return Ok(sub.subscribe());
            }
        } // Drop read lock here

        // create node subscription
        let mut subs = self.inner.log_subscriptions.write().await;

        // double-check - another task may have created it while we waited for write lock
        if let Some(sub) = subs.get(&key) {
            return Ok(sub.subscribe());
        }

        let Some(dst_config) = self.inner.chain_configs.get(&packet.dst_chain_id) else {
            return Err(SettlementError::UnsupportedChain(packet.dst_chain_id));
        };

        // subscribe to events emitted by the library
        let stream = dst_config
            .provider
            .subscribe_logs(
                &Filter::new()
                    .address(packet.receive_lib_address)
                    .event_signature(PayloadVerified::SIGNATURE_HASH),
            )
            .await?;

        // spawn the chain subscription
        let subscription = ChainSubscription::spawn(key, stream, self.clone());
        let rx = subscription.subscribe();
        subs.insert(key, subscription);

        info!(
            chain_id = packet.dst_chain_id,
            receive_lib_address = ?packet.receive_lib_address,
            settler_address = ?packet.receiver,
            "Created subscription for chain and receive library combination"
        );

        Ok(rx)
    }

    /// Try to cleanup a chain subscription if it has no active receivers.
    ///
    /// Returns true if the subscription was removed, false otherwise.
    async fn try_cleanup(&self, key: SubscriptionKey) -> bool {
        let mut subs = self.inner.log_subscriptions.write().await;
        if let Some(subscription) = subs.get(&key) {
            // double-check that there are truly no subscribers
            if subscription.handle.subscribers_count.load(Ordering::Acquire) == 0 {
                subs.remove(&key);
                info!(chain_id = key.chain_id, receive_lib = ?key.receive_library, "Removed unused chain subscription");
                return true;
            }
        }
        false
    }

    /// Force remove a chain subscription regardless of subscriber count.
    ///
    /// Used when the stream encounters an error and needs to be recreated.
    async fn force_cleanup(&self, key: SubscriptionKey) {
        let mut subs = self.inner.log_subscriptions.write().await;
        if subs.remove(&key).is_some() {
            warn!(chain_id = key.chain_id, receive_lib = ?key.receive_library, "Force removed chain subscription due to stream error");
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

impl VerificationResult {
    /// Creates a new verification result by checking which packets were verified.
    ///
    /// Takes verified GUIDs and all packets, partitioning them into verified and failed.
    fn new(
        verified_guids: impl IntoIterator<Item = B256>,
        all_packets: &[LayerZeroPacketInfo],
    ) -> Self {
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
            warn!(
                "Failed to verify {} out of {} messages",
                failed_packets.len(),
                all_packets.len()
            );
        }

        Self { verified_packets, failed_packets }
    }
}

/// Handle to a chain's event stream for a specific packet.
///
/// When dropped, decrements the subscriber count for its chain subscription.
#[derive(Debug)]
pub struct PacketSubscription {
    /// The underlying broadcast receiver for header hashes of `PayloadVerified` events
    inner: broadcast::Receiver<B256>,
    /// Handle for cleanup when dropped
    chain_handle: ChainSubscriptionHandle,
}

impl Drop for PacketSubscription {
    fn drop(&mut self) {
        self.chain_handle.notify_drop();
    }
}
