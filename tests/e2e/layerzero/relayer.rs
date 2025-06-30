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

use alloy::{
    network::Ethereum,
    primitives::{Address, B256, Bytes, U256, keccak256},
    providers::{Provider, ProviderBuilder, ext::AnvilApi},
    rpc::types::{Filter, Log},
    sol,
    sol_types::SolEvent,
};
use eyre::Result;
use std::{collections::HashSet, sync::Arc};
use tokio::{sync::Mutex, task::JoinHandle};

sol! {
    #[sol(rpc)]
    interface IEndpointV2Mock {
        struct Origin {
            uint32 srcEid;
            bytes32 sender;
            uint64 nonce;
        }

        event PacketSent(bytes encodedPayload, bytes options, address sendLibrary);

        function verify(Origin calldata origin, address receiver, bytes32 payloadHash) external;
        function lzReceive(
            Origin calldata origin,
            address receiver,
            bytes32 guid,
            bytes calldata message,
            bytes calldata extraData
        ) external payable;

        function registerLibrary(address _lib) external;
        function setDefaultSendLibrary(uint32 _eid, address _newLib) external;
        function setDefaultReceiveLibrary(uint32 _eid, address _newLib, uint256 _timeout) external;
    }

    #[sol(rpc)]
    interface IMessageLibManager {
        function defaultReceiveLibrary(uint32 _eid) external view returns (address);
    }
}

sol! {
    struct Packet {
        uint64 nonce;
        uint32 srcEid;
        address sender;
        uint32 dstEid;
        bytes32 receiver;
        bytes32 guid;
        bytes message;
    }
}

#[derive(Clone)]
pub struct ChainEndpoint {
    pub chain_index: usize,
    pub endpoint: Address,
    pub eid: u32,
}

pub struct LayerZeroRelayer {
    endpoints: Vec<ChainEndpoint>,
    rpc_urls: Vec<String>,
    delivered_guids: Arc<Mutex<HashSet<B256>>>,
}

impl LayerZeroRelayer {
    pub fn new(endpoints: Vec<ChainEndpoint>, rpc_urls: Vec<String>) -> Self {
        Self { endpoints, rpc_urls, delivered_guids: Arc::new(Mutex::new(HashSet::new())) }
    }

    /// Starts monitoring tasks for all configured chains
    pub async fn start(self: Arc<Self>) -> Result<Vec<JoinHandle<Result<()>>>> {
        let mut handles = Vec::with_capacity(self.endpoints.len());

        for endpoint in &self.endpoints {
            let relayer = self.clone();
            let endpoint = endpoint.clone();

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
        let provider = self.create_provider_no_wallet(chain_endpoint.chain_index).await?;

        let filter = Filter::new()
            .address(chain_endpoint.endpoint)
            .event_signature(IEndpointV2Mock::PacketSent::SIGNATURE_HASH);

        let mut stream = provider.subscribe_logs(&filter).await?;

        while let Ok(log) = stream.recv().await {
            if let Err(e) = self.handle_packet_sent(log, &chain_endpoint).await {
                eprintln!(
                    "Error handling PacketSent event on chain {}: {e:?}",
                    chain_endpoint.chain_index
                );
            }
        }

        Ok(())
    }

    /// Handles a PacketSent event by decoding and delivering the message
    async fn handle_packet_sent(&self, log: Log, source_endpoint: &ChainEndpoint) -> Result<()> {
        let event = IEndpointV2Mock::PacketSent::decode_log(&log.inner)?;
        let packet = self.decode_packet(&event.encodedPayload)?;

        // Check if already delivered
        if !self.mark_as_delivered(packet.guid).await {
            return Ok(());
        }

        let dst_endpoint = self
            .endpoints
            .iter()
            .find(|e| e.eid == packet.dstEid)
            .ok_or_else(|| eyre::eyre!("Unknown destination eid: {}", packet.dstEid))?;

        self.deliver_message(source_endpoint, dst_endpoint, packet, event.options.clone()).await
    }

    /// Marks a GUID as delivered, returns true if it's new
    async fn mark_as_delivered(&self, guid: B256) -> bool {
        let mut delivered = self.delivered_guids.lock().await;
        delivered.insert(guid)
    }

    /// Delivers a message to the destination chain
    async fn deliver_message(
        &self,
        _src_endpoint: &ChainEndpoint,
        dst_endpoint: &ChainEndpoint,
        packet: Packet,
        _options: Bytes,
    ) -> Result<()> {
        let origin = self.create_origin(&packet);
        let receiver = self.extract_receiver_address(&packet.receiver)?;
        let payload = [packet.guid.as_slice(), packet.message.as_ref()].concat();
        let payload_hash = keccak256(&payload);

        let provider = self.create_provider_no_wallet(dst_endpoint.chain_index).await?;

        // Verify the message
        self.verify_message(
            &provider,
            dst_endpoint.endpoint,
            &origin,
            receiver,
            payload_hash,
            packet.srcEid,
        )
        .await?;

        // Execute lzReceive
        self.execute_lz_receive(
            &provider,
            dst_endpoint.endpoint,
            &origin,
            receiver,
            packet.guid,
            packet.message,
        )
        .await
    }

    /// Creates an origin struct from a packet
    fn create_origin(&self, packet: &Packet) -> IEndpointV2Mock::Origin {
        IEndpointV2Mock::Origin {
            srcEid: packet.srcEid,
            sender: B256::from_slice(&[&[0u8; 12], packet.sender.as_slice()].concat()),
            nonce: packet.nonce,
        }
    }

    /// Extracts the receiver address from a 32-byte receiver field
    fn extract_receiver_address(&self, receiver: &B256) -> Result<Address> {
        Ok(Address::from_slice(&receiver[12..]))
    }

    /// Verifies a message using the receive library
    async fn verify_message<P: Provider + AnvilApi<Ethereum>>(
        &self,
        provider: &P,
        endpoint_addr: Address,
        origin: &IEndpointV2Mock::Origin,
        receiver: Address,
        payload_hash: B256,
        src_eid: u32,
    ) -> Result<()> {
        let lib_manager = IMessageLibManager::new(endpoint_addr, provider);
        let receive_lib = lib_manager.defaultReceiveLibrary(src_eid).call().await?;

        // Fund and impersonate receive library
        provider.anvil_set_balance(receive_lib, U256::from(1e18)).await?;
        provider.anvil_impersonate_account(receive_lib).await?;

        let endpoint = IEndpointV2Mock::new(endpoint_addr, provider);
        endpoint
            .verify(origin.clone(), receiver, payload_hash)
            .from(receive_lib)
            .send()
            .await?
            .watch()
            .await?;

        provider.anvil_stop_impersonating_account(receive_lib).await?;
        Ok(())
    }

    /// Executes the lzReceive function
    async fn execute_lz_receive<P: Provider + AnvilApi<Ethereum>>(
        &self,
        provider: &P,
        endpoint_addr: Address,
        origin: &IEndpointV2Mock::Origin,
        receiver: Address,
        guid: B256,
        message: Bytes,
    ) -> Result<()> {
        const EXECUTOR_ADDRESS: Address = Address::new([3u8; 20]);

        // Fund and impersonate executor
        provider.anvil_set_balance(EXECUTOR_ADDRESS, U256::from(1e18)).await?;
        provider.anvil_impersonate_account(EXECUTOR_ADDRESS).await?;

        let endpoint = IEndpointV2Mock::new(endpoint_addr, provider);
        endpoint
            .lzReceive(origin.clone(), receiver, guid, message, Bytes::new())
            .from(EXECUTOR_ADDRESS)
            .send()
            .await?
            .watch()
            .await?;

        provider.anvil_stop_impersonating_account(EXECUTOR_ADDRESS).await?;
        Ok(())
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
            sender: self.extract_sender_address(&data[OFFSETS.sender..OFFSETS.dst_eid])?,
            dstEid: u32::from_be_bytes(data[OFFSETS.dst_eid..OFFSETS.receiver].try_into()?),
            receiver: B256::from_slice(&data[OFFSETS.receiver..OFFSETS.guid]),
            guid: B256::from_slice(&data[OFFSETS.guid..OFFSETS.message]),
            message: Bytes::from(data[OFFSETS.message..].to_vec()),
        })
    }

    /// Extracts sender address from 32-byte field (last 20 bytes)
    fn extract_sender_address(&self, data: &[u8]) -> Result<Address> {
        let sender_bytes32 = B256::from_slice(data);
        Ok(Address::from_slice(&sender_bytes32[12..]))
    }

    /// Creates a provider without wallet for the specified chain
    async fn create_provider_no_wallet(
        &self,
        chain_index: usize,
    ) -> Result<impl Provider + AnvilApi<Ethereum>> {
        let rpc_url = self
            .rpc_urls
            .get(chain_index)
            .ok_or_else(|| eyre::eyre!("No RPC URL for chain index {}", chain_index))?;

        // Convert to WebSocket URL for subscription support
        let ws_url = rpc_url.replace("http://", "ws://").replace("https://", "wss://");

        Ok(ProviderBuilder::new().connect(&ws_url).await?)
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
