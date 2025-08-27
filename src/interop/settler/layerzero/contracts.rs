//! LayerZero contract interfaces
//!
//! This module contains the Solidity interface definitions for LayerZero contracts.

use alloy::{
    primitives::{Address, B256, U256, bytes},
    sol,
    sol_types::SolValue,
};

sol! {
    /// LayerZero settler interface
    #[derive(Debug)]
    #[sol(rpc)]
    interface ILayerZeroSettler {
        function send(bytes32 settlementId, bytes calldata settlerContext) external payable;
        function executeSend(address sender, bytes32 settlementId, bytes calldata settlerContext)
            external
            payable;
        function peers(uint32 _eid) external view returns (bytes32 peer);
    }

    /// ULN configuration structure
    #[derive(Debug)]
    struct UlnConfig {
        uint64 confirmations;
        uint8 requiredDVNCount;
        uint8 optionalDVNCount;
        uint8 optionalDVNThreshold;
        address[] requiredDVNs;
        address[] optionalDVNs;
    }

    /// ReceiveUln302 interface for committing verification
    #[sol(rpc)]
    interface IReceiveUln302 {
        #[derive(Debug)]
        event PayloadVerified(address dvn, bytes header, uint256 confirmations, bytes32 proofHash);

        function commitVerification(bytes calldata _packetHeader, bytes32 _payloadHash) external;
        function verifiable(UlnConfig memory _config, bytes32 _headerHash, bytes32 _payloadHash) external view returns (bool);
        function getUlnConfig(address _oapp, uint32 _remoteEid) external view returns (UlnConfig memory);
    }

    /// LayerZero messaging parameters
    #[derive(Debug)]
    struct MessagingParams {
        uint32 dstEid;
        bytes32 receiver;
        bytes message;
        bytes options;
        bool payInLzToken;
    }

    /// LayerZero messaging fee
    #[derive(Debug)]
    struct MessagingFee {
        uint256 nativeFee;
        uint256 lzTokenFee;
    }

    /// LayerZero origin
    #[derive(Debug)]
    struct Origin {
        uint32 srcEid;
        bytes32 sender;
        uint64 nonce;
    }

    /// LayerZero Endpoint V2 interface
    #[sol(rpc)]
    #[derive(Debug)]
    interface ILayerZeroEndpointV2 {
        event PacketSent(bytes encodedPayload, bytes options, address sendLibrary);

        event PacketVerified(Origin origin, address receiver, bytes32 payloadHash);

        function quote(MessagingParams calldata _params, address _sender) external view returns (MessagingFee memory);
        function inboundNonce(address _receiver, uint32 _srcEid, bytes32 _sender) external view returns (uint64);
        function inboundPayloadHash(address _receiver, uint32 _srcEid, bytes32 _sender, uint64 _nonce) external view returns (bytes32 payloadHash);
        function getReceiveLibrary(address _receiver, uint32 _eid) external view returns (address lib, bool isDefault);
        function verifiable(Origin calldata _origin, address _receiver) external view returns (bool);
        function lzReceive(Origin calldata _origin, address _receiver, bytes32 _guid, bytes calldata _message, bytes calldata _extraData) external payable;
        function registerLibrary(address _lib) external;
        function setDefaultSendLibrary(uint32 _eid, address _newLib) external;
        function setDefaultReceiveLibrary(uint32 _eid, address _newLib, uint256 _timeout) external;
        function getConfig(address _oapp, address _lib, uint32 _eid, uint32 _configType) external view returns (bytes memory config);
    }
}

impl MessagingParams {
    /// Creates LayerZero messaging parameters for settlement messages.
    pub fn new(src_chain_id: u64, dst_eid: u32, receiver: Address, settlement_id: B256) -> Self {
        Self {
            dstEid: dst_eid,
            receiver: B256::left_padding_from(receiver.as_slice()),
            message: (settlement_id, receiver, U256::from(src_chain_id)).abi_encode().into(),
            options: bytes!("0x0003"), // Version 3
            payInLzToken: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interop::settler::layerzero::{
        ULN_CONFIG_TYPE,
        contracts::ILayerZeroSettler::{executeSendCall, sendCall},
    };
    use alloy::{
        primitives::{Bytes, address},
        providers::{CallItem, MULTICALL3_ADDRESS, Provider, ProviderBuilder},
    };

    #[tokio::test]
    async fn test_layerzero_quote_ethereum_mainnet() {
        // Test configuration for Ethereum mainnet
        let ethereum_mainnet_url = "https://reth-ethereum.ithaca.xyz/rpc";
        let ethereum_mainnet_endpoint = address!("0x1a44076050125825900e736c501f859c50fE728c");
        let optimism_eid: u32 = 30111; // Optimism mainnet EID
        let settler_address = address!("0xF387a549986cC804e19Ef23c2D55b9a5eF053944");
        let ethereum_provider =
            ProviderBuilder::new().connect_http(ethereum_mainnet_url.parse().unwrap());
        let endpoint = ILayerZeroEndpointV2::new(ethereum_mainnet_endpoint, &ethereum_provider);
        let settlement_id = B256::random();

        let params = MessagingParams::new(
            1, // Ethereum mainnet chain ID
            optimism_eid,
            settler_address,
            settlement_id,
        );

        let quote = endpoint.quote(params, settler_address).call().await.unwrap();
        println!(
            "Quote: nativeFee = {} wei, lzTokenFee = {} wei",
            quote.nativeFee, quote.lzTokenFee
        );

        // Test send + executeSend with multicall
        let settler_contract = ILayerZeroSettler::new(settler_address, &ethereum_provider);
        let settler_context: Bytes = vec![optimism_eid].abi_encode().into(); // ABI-encoded remote EID

        // Build multicall: first send(), then executeSend()
        let (send, execute_send) = ethereum_provider
            .multicall()
            .add_call::<sendCall>(
                CallItem::from(settler_contract.send(settlement_id, settler_context.clone()))
                    .allow_failure(true),
            )
            .add_call::<executeSendCall>(
                CallItem::from(settler_contract.executeSend(
                    MULTICALL3_ADDRESS,
                    settlement_id,
                    settler_context,
                ))
                .value(quote.nativeFee)
                .allow_failure(true),
            )
            .aggregate3_value()
            .await
            .unwrap();

        send.unwrap();
        execute_send.unwrap();
    }

    #[tokio::test]
    async fn test_layerzero_diagnostics_ethereum_mainnet() {
        let ethereum_provider = ProviderBuilder::new()
            .connect_http("https://reth-ethereum.ithaca.xyz/rpc".parse().unwrap());
        let endpoint = ILayerZeroEndpointV2::new(
            address!("0x1a44076050125825900e736c501f859c50fE728c"),
            &ethereum_provider,
        );
        let settler = address!("0xF387a549986cC804e19Ef23c2D55b9a5eF053944");
        let optimism_eid = 30111u32; // Optimism mainnet EID

        // Receive lib + ULN config via getConfig
        let lib_info = endpoint.getReceiveLibrary(settler, optimism_eid).call().await.unwrap();
        let config_bytes = endpoint
            .getConfig(settler, lib_info.lib, optimism_eid, ULN_CONFIG_TYPE)
            .call()
            .await
            .unwrap();
        let uln_config = UlnConfig::abi_decode(&config_bytes).unwrap();
        println!("Lib: {lib_info:?}");
        println!("ULN: {uln_config:?}");
    }
}
