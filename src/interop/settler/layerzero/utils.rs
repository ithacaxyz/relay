use alloy::{
    primitives::{Address, B256, FixedBytes},
    sol_types::SolEvent,
};

/// Empty payload hash constant used by LayerZero
pub const EMPTY_PAYLOAD_HASH: B256 = B256::ZERO;

alloy::sol! {
    #[derive(Debug)]
    event PacketSent(
        bytes encodedPayload,
        bytes options,
        address sendLibrary
    );
}

/// LayerZero packet structure
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerZeroPacket {
    /// Packet nonce for ordering and uniqueness
    pub nonce: u64,
    /// Source endpoint ID
    pub src_eid: u32,
    /// Sender address (32 bytes)
    pub sender: FixedBytes<32>,
    /// Destination endpoint ID
    pub dst_eid: u32,
    /// Receiver address (32 bytes)
    pub receiver: FixedBytes<32>,
    /// Globally unique identifier for the packet
    pub guid: FixedBytes<32>,
    /// The actual message payload
    pub message: Vec<u8>,
}

/// Decode a PacketSent event from raw log data
/// Decode a PacketSent event from raw log data
pub fn decode_packet_sent_event(
    data: &[u8],
    topics: &[B256],
) -> Result<(Vec<u8>, Vec<u8>, Address), String> {
    // PacketSent event has topic[0] as event signature
    if topics.is_empty() {
        return Err("Missing event signature topic".to_string());
    }

    // Decode the event data
    let event = PacketSent::decode_raw_log(topics, data)
        .map_err(|e| format!("Failed to decode PacketSent event: {e}"))?;

    Ok((event.encodedPayload.to_vec(), event.options.to_vec(), event.sendLibrary))
}

/// Decode a LayerZero packet from encoded payload
pub fn decode_packet(encoded_payload: &[u8]) -> Result<LayerZeroPacket, String> {
    // LayerZero packet encoding (v1):
    // version (1 byte) + nonce (8 bytes) + srcEid (4 bytes) + sender (32 bytes) +
    // dstEid (4 bytes) + receiver (32 bytes) + guid (32 bytes) + message

    if encoded_payload.len() < 113 {
        return Err(
            "Encoded payload too short for LayerZero packet (minimum 113 bytes)".to_string()
        );
    }

    let mut offset = 0;

    // Decode version (1 byte) - must be 1
    let version = encoded_payload[offset];
    if version != 1 {
        return Err(format!("Invalid packet version: expected 1, got {version}"));
    }
    offset += 1;

    // Decode nonce (8 bytes) - offset 1
    let nonce = u64::from_be_bytes(
        encoded_payload[offset..offset + 8]
            .try_into()
            .map_err(|_| "Failed to decode nonce".to_string())?,
    );
    offset += 8;

    // Decode srcEid (4 bytes) - offset 9
    let src_eid = u32::from_be_bytes(
        encoded_payload[offset..offset + 4]
            .try_into()
            .map_err(|_| "Failed to decode srcEid".to_string())?,
    );
    offset += 4;

    // Decode sender (32 bytes) - offset 13
    let sender = FixedBytes::<32>::from_slice(&encoded_payload[offset..offset + 32]);
    offset += 32;

    // Decode dstEid (4 bytes) - offset 45
    let dst_eid = u32::from_be_bytes(
        encoded_payload[offset..offset + 4]
            .try_into()
            .map_err(|_| "Failed to decode dstEid".to_string())?,
    );
    offset += 4;

    // Decode receiver (32 bytes) - offset 49
    let receiver = FixedBytes::<32>::from_slice(&encoded_payload[offset..offset + 32]);
    offset += 32;

    // Decode guid (32 bytes) - offset 81
    let guid = FixedBytes::<32>::from_slice(&encoded_payload[offset..offset + 32]);
    offset += 32;

    // Remaining bytes are the message - offset 113
    let message = encoded_payload[offset..].to_vec();

    Ok(LayerZeroPacket { nonce, src_eid, sender, dst_eid, receiver, guid, message })
}

/// Convert an Address to FixedBytes<32> (left-padded with zeros)
pub fn address_to_bytes32(address: Address) -> FixedBytes<32> {
    let mut bytes = [0u8; 32];
    bytes[12..].copy_from_slice(address.as_slice());
    FixedBytes::from(bytes)
}

/// Convert FixedBytes<32> to Address (taking last 20 bytes)
pub fn bytes32_to_address(bytes: FixedBytes<32>) -> Result<Address, String> {
    // Check that the first 12 bytes are zeros (standard address encoding)
    if bytes[..12].iter().any(|&b| b != 0) {
        return Err("Invalid address encoding in bytes32".to_string());
    }

    Ok(Address::from_slice(&bytes[12..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::MULTICALL3_ADDRESS;

    #[test]
    fn test_address_conversions() {
        let addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f62Ce6".parse::<Address>().unwrap();

        let bytes32 = address_to_bytes32(addr);
        assert_eq!(bytes32[..12], [0u8; 12]);
        assert_eq!(&bytes32[12..], addr.as_slice());

        let converted_back = bytes32_to_address(bytes32).unwrap();
        assert_eq!(converted_back, addr);
    }

    #[test]
    fn test_decode_packet() {
        // Create a mock encoded packet
        let mut encoded = Vec::new();

        // version (1 byte) - must be 1
        encoded.push(1u8);

        // nonce (8 bytes)
        encoded.extend_from_slice(&1u64.to_be_bytes());

        // srcEid (4 bytes)
        encoded.extend_from_slice(&30101u32.to_be_bytes());

        // sender (32 bytes)
        let sender_addr = "0x742d35Cc6634C0532925a3b844Bc9e7595f62Ce6".parse::<Address>().unwrap();
        encoded.extend_from_slice(address_to_bytes32(sender_addr).as_slice());

        // dstEid (4 bytes)
        encoded.extend_from_slice(&30111u32.to_be_bytes());

        // receiver (32 bytes)
        let receiver_addr =
            "0x853d955aCEf822Db058eb8505911ED77F175b99e".parse::<Address>().unwrap();
        encoded.extend_from_slice(address_to_bytes32(receiver_addr).as_slice());

        // guid (32 bytes)
        let guid = FixedBytes::<32>::from([1u8; 32]);
        encoded.extend_from_slice(guid.as_slice());

        // message
        let message = b"Hello LayerZero";
        encoded.extend_from_slice(message);

        // Decode the packet
        let packet = decode_packet(&encoded).unwrap();

        assert_eq!(packet.nonce, 1);
        assert_eq!(packet.src_eid, 30101);
        assert_eq!(packet.sender, address_to_bytes32(sender_addr));
        assert_eq!(packet.dst_eid, 30111);
        assert_eq!(packet.receiver, address_to_bytes32(receiver_addr));
        assert_eq!(packet.guid, guid);
        assert_eq!(packet.message, message);
    }

    #[test]
    fn test_decode_packet_invalid_version() {
        // Create a packet with invalid version
        let mut encoded = Vec::new();
        encoded.push(2u8); // Invalid version
        encoded.extend_from_slice(&[0u8; 112]); // Fill rest with zeros

        let result = decode_packet(&encoded);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Invalid packet version: expected 1, got 2");
    }

    #[test]
    fn test_decode_packet_too_short() {
        // Create a packet that's too short
        let encoded = vec![1u8; 112]; // 1 byte short

        let result = decode_packet(&encoded);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Encoded payload too short for LayerZero packet (minimum 113 bytes)"
        );
    }

    #[test]
    fn test_multicall_address() {
        // Test multicall constant
        assert_eq!(
            MULTICALL3_ADDRESS,
            "0xcA11bde05977b3631167028862bE2a173976CA11".parse::<Address>().unwrap()
        );
    }
}
