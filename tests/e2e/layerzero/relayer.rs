//! LayerZero message relayer implementation
//!
//! This module implements an automated LayerZero message relayer that monitors
//! PacketSent events on source chains and automatically delivers them to
//! destination chains.
//!
//! ## Architecture
//!
//! The relayer consists of:
//! - **Event Monitoring**: Subscribes to PacketSent events on each endpoint
//! - **Message Verification**: Uses the receive library to verify messages
//! - **Message Delivery**: Executes lzReceive on destination endpoints
//! - **Duplicate Prevention**: Tracks delivered GUIDs to prevent redelivery

use super::{
    interfaces::{IEndpointV2Mock, Packet},
    utils::{bytes32_to_address, create_origin, deliver_layerzero_message},
};
use alloy::{
    primitives::{Address, B256, Bytes},
    providers::{DynProvider, Provider, ProviderBuilder, WsConnect},
    rpc::types::{Filter, Log},
    sol_types::SolEvent,
};
use eyre::Result;
use parking_lot::Mutex;
use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::task::JoinHandle;

#[derive(Clone)]
pub struct ChainEndpoint {
    /// Index matching Environment.providers position
    pub chain_index: usize,
    pub endpoint: Address,
    pub eid: u32,
}

struct LayerZeroRelayerInner {
    endpoints: Vec<ChainEndpoint>,
    providers: Vec<DynProvider>,
    delivered_guids: Mutex<HashSet<B256>>,
    messages_seen: AtomicUsize,
    transactions_sent: AtomicUsize,
}

#[derive(Clone)]
pub struct LayerZeroRelayer {
    inner: Arc<LayerZeroRelayerInner>,
}

impl LayerZeroRelayer {
    pub async fn new(endpoints: Vec<ChainEndpoint>, rpc_urls: Vec<String>) -> Result<Self> {
        // Build WebSocket providers that can handle both subscriptions and regular calls
        // Note: Provider order must match chain_index in endpoints
        let providers = futures_util::future::try_join_all(rpc_urls.iter().map(async |url| {
            let ws_url = url.replace("http://", "ws://").replace("https://", "wss://");
            let provider = ProviderBuilder::new().connect_ws(WsConnect::new(ws_url)).await?;
            Ok::<_, eyre::Error>(provider.erased())
        }))
        .await?;

        Ok(Self {
            inner: Arc::new(LayerZeroRelayerInner {
                endpoints,
                providers,
                delivered_guids: Mutex::new(HashSet::new()),
                messages_seen: AtomicUsize::new(0),
                transactions_sent: AtomicUsize::new(0),
            }),
        })
    }

    /// Starts monitoring tasks for all configured chains
    pub async fn start(self) -> Result<Vec<JoinHandle<Result<()>>>> {
        let mut handles = Vec::with_capacity(self.inner.endpoints.len());

        for endpoint in self.inner.endpoints.iter().cloned() {
            let relayer = self.clone();
            let chain_index = endpoint.chain_index;
            let handle = tokio::spawn(async move {
                if let Err(e) = relayer.monitor_chain(endpoint).await {
                    eprintln!("LayerZero Relayer error on chain {chain_index}: {e:?}");
                }
                Ok(())
            });

            handles.push(handle);
        }

        Ok(handles)
    }

    /// Monitors a single chain for PacketSent events
    ///
    /// Subscribes to the endpoint's PacketSent events and processes
    /// each one by delivering it to the appropriate destination.
    async fn monitor_chain(&self, chain_endpoint: ChainEndpoint) -> Result<()> {
        let provider = &self.inner.providers[chain_endpoint.chain_index];

        let filter = Filter::new()
            .address(chain_endpoint.endpoint)
            .event_signature(IEndpointV2Mock::PacketSent::SIGNATURE_HASH);

        let mut stream = provider.subscribe_logs(&filter).await?;

        while let Ok(log) = stream.recv().await {
            if let Err(e) = self.handle_packet_sent(log).await {
                eprintln!(
                    "Error handling PacketSent event on chain {}: {e:?}",
                    chain_endpoint.chain_index
                );
            }
        }

        Ok(())
    }

    /// Handles a PacketSent event by decoding and delivering the message
    async fn handle_packet_sent(&self, log: Log) -> Result<()> {
        let event = IEndpointV2Mock::PacketSent::decode_log(&log.inner)?;
        let packet = self.decode_packet(&event.encodedPayload)?;

        // Increment messages seen counter
        self.inner.messages_seen.fetch_add(1, Ordering::Relaxed);

        // Check if already delivered
        if !self.mark_as_delivered(packet.guid) {
            return Ok(());
        }

        let dst_endpoint = self
            .inner
            .endpoints
            .iter()
            .find(|e| e.eid == packet.dstEid)
            .ok_or_else(|| eyre::eyre!("Unknown destination eid: {}", packet.dstEid))?;

        self.deliver_message(dst_endpoint, packet).await
    }

    /// Marks a GUID as delivered, returns true if it's new
    fn mark_as_delivered(&self, guid: B256) -> bool {
        let mut delivered = self.inner.delivered_guids.lock();
        delivered.insert(guid)
    }

    /// Delivers a message to the destination chain
    async fn deliver_message(&self, dst_endpoint: &ChainEndpoint, packet: Packet) -> Result<()> {
        let result = deliver_layerzero_message(
            &self.inner.providers[dst_endpoint.chain_index],
            dst_endpoint.endpoint,
            packet.srcEid,
            &create_origin(packet.srcEid, packet.sender, packet.nonce),
            bytes32_to_address(&packet.receiver),
            packet.guid,
            packet.message,
        )
        .await;

        // Increment transactions sent counter on success
        if result.is_ok() {
            self.inner.transactions_sent.fetch_add(1, Ordering::Relaxed);
        }

        result
    }

    /// Decodes a LayerZero packet from encoded bytes
    fn decode_packet(&self, encoded: &Bytes) -> Result<Packet> {
        // PacketV1Codec field offsets
        const OFFSETS: PacketOffsets = PacketOffsets {
            version: 0,
            nonce: 1,
            src_eid: 9,
            sender: 13,
            dst_eid: 45,
            receiver: 49,
            guid: 81,
            message: 113,
        };

        let data = encoded.as_ref();

        if data.len() < OFFSETS.message {
            return Err(eyre::eyre!(
                "Encoded packet too short: {} bytes, need at least {}",
                data.len(),
                OFFSETS.message
            ));
        }

        // Verify packet version
        let version = data[OFFSETS.version];
        if version != 1 {
            return Err(eyre::eyre!("Unsupported packet version: {}", version));
        }

        Ok(Packet {
            nonce: u64::from_be_bytes(data[OFFSETS.nonce..OFFSETS.src_eid].try_into()?),
            srcEid: u32::from_be_bytes(data[OFFSETS.src_eid..OFFSETS.sender].try_into()?),
            sender: bytes32_to_address(&B256::from_slice(&data[OFFSETS.sender..OFFSETS.dst_eid])),
            dstEid: u32::from_be_bytes(data[OFFSETS.dst_eid..OFFSETS.receiver].try_into()?),
            receiver: B256::from_slice(&data[OFFSETS.receiver..OFFSETS.guid]),
            guid: B256::from_slice(&data[OFFSETS.guid..OFFSETS.message]),
            message: Bytes::from(data[OFFSETS.message..].to_vec()),
        })
    }

    /// Gets the number of messages seen by the relayer
    pub fn messages_seen(&self) -> usize {
        self.inner.messages_seen.load(Ordering::Relaxed)
    }

    /// Gets the number of transactions sent by the relayer
    pub fn transactions_sent(&self) -> usize {
        self.inner.transactions_sent.load(Ordering::Relaxed)
    }
}

/// Packet field offsets for decoding
struct PacketOffsets {
    version: usize,
    nonce: usize,
    src_eid: usize,
    sender: usize,
    dst_eid: usize,
    receiver: usize,
    guid: usize,
    message: usize,
}
