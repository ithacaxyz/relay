// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { ISendLib, Packet } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ISendLib.sol";
import { MessagingFee } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { IMessageLib, MessageLibType } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/IMessageLib.sol";
import { SetConfigParam } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/IMessageLibManager.sol";
import { PacketV1Codec } from "@layerzerolabs/lz-evm-protocol-v2/contracts/messagelib/libs/PacketV1Codec.sol";
import { ERC165, IERC165 } from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

// Minimal implementation that provides just enough functionality for testing
contract MinimalSendReceiveLib is ISendLib, ERC165 {
    using PacketV1Codec for bytes;
    
    uint256 public constant NATIVE_FEE = 0.001 ether;
    
    function send(
        Packet calldata _packet,
        bytes calldata _options,
        bool _payInLzToken
    ) external pure returns (MessagingFee memory fee, bytes memory encodedPacket) {
        fee = MessagingFee(NATIVE_FEE, _payInLzToken ? 100 : 0);
        encodedPacket = PacketV1Codec.encode(_packet);
    }
    
    function quote(
        Packet calldata,
        bytes calldata,
        bool _payInLzToken
    ) external pure returns (MessagingFee memory) {
        return MessagingFee(NATIVE_FEE, _payInLzToken ? 100 : 0);
    }
    
    // Common interface methods
    function version() external pure returns (uint64 major, uint8 minor, uint8 endpointVersion) {
        return (1, 0, 2);
    }
    
    function messageLibType() external pure returns (MessageLibType) {
        return MessageLibType.SendAndReceive;
    }
    
    function isSupportedEid(uint32) external pure returns (bool) {
        return true;
    }
    
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(ISendLib).interfaceId || 
               interfaceId == type(IMessageLib).interfaceId ||
               super.supportsInterface(interfaceId);
    }
    
    // Config management (no-op for testing)
    function setConfig(address, SetConfigParam[] calldata) external pure {}
    
    function getConfig(uint32, address, uint32) external pure returns (bytes memory) {
        return "";
    }
    
    // Treasury management (no-op for testing)
    function setTreasury(address) external pure {}
    
    function withdrawLzTokenFee(address, address, uint256) external pure {}
    
    function withdrawFee(address, uint256) external pure {}
    
    // Accept ETH payments
    receive() external payable {}
}