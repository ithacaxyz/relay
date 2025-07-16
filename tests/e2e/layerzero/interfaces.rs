//! LayerZero contract interfaces and type definitions
//!
//! This module contains all Solidity interface definitions used in LayerZero tests.

use alloy::sol;

/// Config type constant for ULN
pub const ULN_CONFIG_TYPE: u32 = 2;

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

    /// LayerZero MessageLibManager interface
    #[sol(rpc)]
    interface IMessageLibManager {
        function defaultReceiveLibrary(uint32 _eid) external view returns (address);
        function setConfig(address _oapp, address _lib, SetConfigParam[] calldata _params) external;
    }

    /// SetConfigParam struct for LayerZero configuration
    struct SetConfigParam {
        uint32 eid;
        uint32 configType;
        bytes config;
    }

    /// OApp interface for LayerZero applications
    #[sol(rpc)]
    interface IOApp {
        function setPeer(uint32 eid, bytes32 peer) external;
    }

    /// IReceiveUlnE2 interface for LayerZero ULN verification
    #[sol(rpc)]
    interface IReceiveUlnE2 {
        /// For each DVN to verify the payload
        function verify(bytes calldata _packetHeader, bytes32 _payloadHash, uint64 _confirmations) external;

        /// Verify the payload at endpoint, will check if all DVNs verified
        function commitVerification(bytes calldata _packetHeader, bytes32 _payloadHash) external;
    }

    // ULN config structure
    struct UlnConfig {
        uint64 confirmations;
        uint8 requiredDVNCount;
        uint8 optionalDVNCount;
        uint8 optionalDVNThreshold;
        address[] requiredDVNs;
        address[] optionalDVNs;
    }

}
