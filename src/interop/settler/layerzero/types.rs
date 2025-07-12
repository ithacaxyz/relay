use alloy::{
    primitives::{Address, B256, Bytes, ChainId, U256},
    sol_types::SolValue,
};
use serde::{Deserialize, Serialize};

/// LayerZero packet information for cross-chain messaging
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
}

impl LayerZeroPacketInfo {
    /// Decodes and returns the settlement ID from the message
    pub fn settlement_id(&self) -> Result<B256, String> {
        let (settlement_id, _, _) = <(B256, Address, U256)>::abi_decode(&self.message)
            .map_err(|e| format!("Failed to decode settlement_id from message: {e}"))?;
        Ok(settlement_id)
    }
}

/// LayerZero PacketV1 packet structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerZeroPacketV1 {
    /// Packet nonce for ordering and uniqueness
    pub nonce: u64,
    /// Source endpoint ID
    pub src_eid: u32,
    /// Sender address (32 bytes)
    pub sender: B256,
    /// Destination endpoint ID
    pub dst_eid: u32,
    /// Receiver address (32 bytes)
    pub receiver: B256,
    /// Globally unique identifier for the packet
    pub guid: B256,
    /// The actual message payload
    pub message: Vec<u8>,
}

impl LayerZeroPacketV1 {
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
