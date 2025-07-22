use crate::interop::settler::layerzero::contracts::{ILayerZeroEndpointV2, Origin, UlnConfig};
use alloy::{
    primitives::{Address, B256, Bytes, ChainId, U256, keccak256},
    sol_types::SolValue,
};

/// LayerZero Endpoint ID (EID) - unique identifier for each blockchain in the LayerZero network.
pub type EndpointId = u32;

/// LayerZero packet information for cross-chain messaging
#[derive(Debug, Clone)]
pub struct LayerZeroPacketInfo {
    /// Source chain ID
    pub src_chain_id: ChainId,
    /// Destination chain ID
    pub dst_chain_id: ChainId,
    /// Nonce for ordering
    pub nonce: u64,
    /// Sender address
    pub sender: Address,
    /// Receiver address
    pub receiver: Address,
    /// Global unique identifier
    pub guid: B256,
    /// Message payload containing (settlement_id, settler_address, source_chain_id)
    pub message: Bytes,
    /// Encoded packet header (needed for commitVerification)
    pub packet_header: Vec<u8>,
    /// Header hash (needed for checking if it's verifiable)
    pub header_hash: B256,
    /// Payload hash (computed from guid + message, needed for both calls mentioned above)
    pub payload_hash: B256,
    /// Receive library address for this packet
    pub receive_lib_address: Address,
    /// ULN configuration for this packet
    pub uln_config: UlnConfig,
}

impl LayerZeroPacketInfo {
    /// Creates a new LayerZeroPacketInfo from a LayerZeroPacketV1 with computed fields
    pub fn new(
        packet: LayerZeroPacketV1,
        src_chain_id: ChainId,
        dst_chain_id: ChainId,
        receive_lib_address: Address,
        uln_config: UlnConfig,
    ) -> Self {
        let sender = Address::from_slice(&packet.sender[12..]);
        let receiver = Address::from_slice(&packet.receiver[12..]);

        let header = packet.encoded_packet_header();
        let header_hash = keccak256(&header);

        let payload = [packet.guid.as_slice(), packet.message.as_ref()].concat();
        let payload_hash = keccak256(&payload);

        Self {
            src_chain_id,
            dst_chain_id,
            nonce: packet.nonce,
            sender,
            receiver,
            guid: packet.guid,
            message: packet.message.into(),
            packet_header: header,
            header_hash,
            payload_hash,
            receive_lib_address,
            uln_config,
        }
    }

    /// Decodes and returns the settlement ID from the message
    pub fn settlement_id(&self) -> Result<B256, String> {
        let (settlement_id, _, _) = <(B256, Address, U256)>::abi_decode(&self.message)
            .map_err(|e| format!("Failed to decode settlement_id from message: {e}"))?;
        Ok(settlement_id)
    }

    /// Builds the LayerZero receive call for message execution.
    pub fn build_lz_receive_call(
        &self,
        src_endpoint_id: u32,
    ) -> ILayerZeroEndpointV2::lzReceiveCall {
        let origin = Origin {
            srcEid: src_endpoint_id,
            sender: B256::left_padding_from(self.sender.as_slice()),
            nonce: self.nonce,
        };

        ILayerZeroEndpointV2::lzReceiveCall {
            _origin: origin,
            _receiver: self.receiver,
            _guid: self.guid,
            _message: self.message.clone(),
            _extraData: Bytes::new(),
        }
    }
}

/// LayerZero PacketV1 packet structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerZeroPacketV1 {
    /// Packet nonce for ordering and uniqueness
    pub nonce: u64,
    /// Source endpoint ID
    pub src_eid: EndpointId,
    /// Sender address (32 bytes)
    pub sender: B256,
    /// Destination endpoint ID
    pub dst_eid: EndpointId,
    /// Receiver address (32 bytes)
    pub receiver: B256,
    /// Globally unique identifier for the packet
    pub guid: B256,
    /// The actual message payload
    pub message: Vec<u8>,
}

impl LayerZeroPacketV1 {
    /// Encodes the packet header in LayerZero V1 format.
    ///
    /// The packet header format is:
    /// - version (1 byte): Always 0x01 for V1
    /// - nonce (8 bytes)
    /// - srcEid (4 bytes)
    /// - sender (32 bytes)
    /// - dstEid (4 bytes)
    /// - receiver (32 bytes)
    pub fn encoded_packet_header(&self) -> Vec<u8> {
        let mut header = Vec::with_capacity(81); // Total header size
        header.push(0x01);
        header.extend_from_slice(&self.nonce.to_be_bytes());
        header.extend_from_slice(&self.src_eid.to_be_bytes());
        header.extend_from_slice(self.sender.as_slice());
        header.extend_from_slice(&self.dst_eid.to_be_bytes());
        header.extend_from_slice(self.receiver.as_slice());
        header
    }

    /// Decodes a LayerZero packet from its encoded payload format.
    ///
    /// LayerZero packets use `abi.encodePacked` format with the following structure:
    /// - `version` (1 byte): Protocol version, must be 1
    /// - `nonce` (8 bytes): Message ordering nonce
    /// - `srcEid` (4 bytes): Source endpoint ID
    /// - `sender` (32 bytes): Sender address (left-padded to 32 bytes)
    /// - `dstEid` (4 bytes): Destination endpoint ID
    /// - `receiver` (32 bytes): Receiver address (left-padded to 32 bytes)
    /// - `guid` (32 bytes): Globally unique identifier
    /// - `message` (variable): The actual message payload
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Payload is shorter than 113 bytes (minimum packet size)
    /// - Version byte is not 1
    pub fn decode(encoded_payload: &[u8]) -> Result<Self, String> {
        const MIN_PACKET_SIZE: usize = 113;
        if encoded_payload.len() < MIN_PACKET_SIZE {
            return Err(format!(
                "Encoded payload too short for LayerZero packet: expected at least {} bytes, got {}",
                MIN_PACKET_SIZE,
                encoded_payload.len()
            ));
        }

        // Check version first
        if encoded_payload[0] != 1 {
            return Err(format!("Invalid packet version: expected 1, got {}", encoded_payload[0]));
        }

        // Since we've validated MIN_PACKET_SIZE, we can safely use expect for known offsets
        let nonce = u64::from_be_bytes(
            encoded_payload[1..9].try_into().expect("nonce slice is exactly 8 bytes"),
        );
        let src_eid = u32::from_be_bytes(
            encoded_payload[9..13].try_into().expect("srcEid slice is exactly 4 bytes"),
        );
        let sender = B256::from_slice(&encoded_payload[13..45]);
        let dst_eid = u32::from_be_bytes(
            encoded_payload[45..49].try_into().expect("dstEid slice is exactly 4 bytes"),
        );
        let receiver = B256::from_slice(&encoded_payload[49..81]);
        let guid = B256::from_slice(&encoded_payload[81..113]);

        // Remaining bytes are the message
        let message = encoded_payload[113..].to_vec();

        Ok(LayerZeroPacketV1 { nonce, src_eid, sender, dst_eid, receiver, guid, message })
    }
}
