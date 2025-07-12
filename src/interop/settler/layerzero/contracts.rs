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
        function lzReceive(Origin calldata _origin, address _receiver, bytes32 _guid, bytes calldata _message, bytes calldata _extraData) external payable;
        function verify(Origin calldata origin, address receiver, bytes32 payloadHash) external;
        function registerLibrary(address _lib) external;
        function setDefaultSendLibrary(uint32 _eid, address _newLib) external;
        function setDefaultReceiveLibrary(uint32 _eid, address _newLib, uint256 _timeout) external;
    }
}
