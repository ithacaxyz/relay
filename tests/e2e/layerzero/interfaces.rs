//! LayerZero contract interfaces and type definitions
//!
//! This module contains all Solidity interface definitions used in LayerZero tests.

use alloy::sol;

sol! {
    /// LayerZero Escrow V2 contract interface
    ///
    /// This interface defines the escrow contract that locks tokens on one chain
    /// and releases them on another chain via LayerZero messaging.
    #[sol(rpc)]
    interface IMockEscrow {
        struct MessagingFee {
            uint256 nativeFee;
            uint256 lzTokenFee;
        }

        function lockTokens(
            address token,
            uint256 amount,
            uint32 dstEid,
            address recipient,
            bytes calldata options
        ) external payable;
        function quoteLayerZeroFee(
            uint32 dstEid,
            address token,
            uint256 amount,
            address recipient,
            bytes calldata options
        ) external view returns (MessagingFee memory fee);
        function lockedBalances(address token, address user) external view returns (uint256);
    }

    /// LayerZero EndpointV2Mock interface
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

    /// LayerZero MessageLibManager interface
    #[sol(rpc)]
    interface IMessageLibManager {
        function defaultReceiveLibrary(uint32 _eid) external view returns (address);
    }

    /// LayerZero packet structure
    struct Packet {
        uint64 nonce;
        uint32 srcEid;
        address sender;
        uint32 dstEid;
        bytes32 receiver;
        bytes32 guid;
        bytes message;
    }

    /// OApp interface for LayerZero applications
    #[sol(rpc)]
    interface IOApp {
        function setPeer(uint32 eid, bytes32 peer) external;
    }
}
