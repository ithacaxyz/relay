//! LayerZero contract interfaces
//!
//! This module contains the Solidity interface definitions for LayerZero contracts.

use alloy::sol;

sol! {
    /// LayerZero settler interface
    interface ILayerZeroSettler {
        function executeSend(address sender, bytes32 settlementId, bytes calldata settlerContext)
            external
            payable;
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
    struct MessagingParams {
        uint32 dstEid;
        bytes32 receiver;
        bytes message;
        bytes options;
        bool payInLzToken;
    }

    /// LayerZero messaging fee
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
    interface ILayerZeroEndpointV2 {
        #[derive(Debug)]
        event PacketSent(bytes encodedPayload, bytes options, address sendLibrary);

        #[derive(Debug)]
        event PacketVerified(Origin origin, address receiver, bytes32 payloadHash);

        function quote(MessagingParams calldata _params, address _sender) external view returns (MessagingFee memory);
        function inboundPayloadHash(address _receiver, uint32 _srcEid, bytes32 _sender, uint64 _nonce) external view returns (bytes32 payloadHash);
        function getReceiveLibrary(address _receiver, uint32 _eid) external view returns (address lib, bool isDefault);
        function verifiable(Origin calldata _origin, address _receiver) external view returns (bool);
        function lzReceive(Origin calldata _origin, address _receiver, bytes32 _guid, bytes calldata _message, bytes calldata _extraData) external payable;
        function registerLibrary(address _lib) external;
        function setDefaultSendLibrary(uint32 _eid, address _newLib) external;
        function setDefaultReceiveLibrary(uint32 _eid, address _newLib, uint256 _timeout) external;
    }
}
