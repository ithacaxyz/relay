// SPDX-License-Identifier: LZBL-1.2
pragma solidity ^0.8.0;

import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";

import { PacketV1Codec } from "@layerzerolabs/lz-evm-protocol-v2/contracts/messagelib/libs/PacketV1Codec.sol";
import { SetConfigParam } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/IMessageLibManager.sol";
import { ILayerZeroEndpointV2, Origin } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { MessagingFee } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { IMessageLib, MessageLibType } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/IMessageLib.sol";
import { IReceiveUlnE2 } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/interfaces/IReceiveUlnE2.sol";
import { ReceiveUlnBase } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/ReceiveUlnBase.sol";
import { ReceiveLibBaseE2 } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/ReceiveLibBaseE2.sol";
import { UlnConfig } from "@layerzerolabs/lz-evm-messagelib-v2/contracts/uln/UlnBase.sol";
import { ISendLib, Packet } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ISendLib.sol";
import { ERC165, IERC165 } from "@openzeppelin/contracts/utils/introspection/ERC165.sol";

contract ReceiveUln302Mock is IReceiveUlnE2, ReceiveUlnBase, ReceiveLibBaseE2, ISendLib {
    using PacketV1Codec for bytes;

    /// @dev CONFIG_TYPE_ULN=2 here to align with SendUln302/ReceiveUln302/ReceiveUln301
    uint32 internal constant CONFIG_TYPE_ULN = 2;

    error LZ_ULN_InvalidConfigType(uint32 configType);

    // @dev oz4/5 breaking change... Ownable constructor
    constructor(address _endpoint) Ownable(msg.sender) ReceiveLibBaseE2(_endpoint) {}

    function supportsInterface(bytes4 interfaceId) public view virtual override(ReceiveLibBaseE2, IERC165) returns (bool) {
        return interfaceId == type(ISendLib).interfaceId || 
               interfaceId == type(IMessageLib).interfaceId ||
               super.supportsInterface(interfaceId);
    }

    function messageLibType() external pure override(ReceiveLibBaseE2, IMessageLib) returns (MessageLibType) {
        return MessageLibType.SendAndReceive;
    }

    // ============================ SendLib ===================================
    
    uint256 public constant NATIVE_FEE = 0.001 ether;

    function quote(
        Packet calldata,
        bytes calldata,
        bool _payInLzToken
    ) external pure returns (MessagingFee memory) {
        return MessagingFee(NATIVE_FEE, _payInLzToken ? 100 : 0);
    }
    
    function send(
        Packet calldata _packet,
        bytes calldata,
        bool _payInLzToken
    ) external pure returns (MessagingFee memory fee, bytes memory encodedPacket) {
        fee = MessagingFee(NATIVE_FEE, _payInLzToken ? 100 : 0);
        encodedPacket = PacketV1Codec.encode(_packet);
    }

    // Treasury management (no-op for testing)
    function setTreasury(address) external pure {}
    
    function withdrawLzTokenFee(address, address, uint256) external pure {}
    
    function withdrawFee(address, uint256) external pure {}
    
    // Accept ETH payments
    receive() external payable {}

    // ============================ OnlyEndpoint ===================================

    // only the ULN config on the receive side
    function setConfig(address _oapp, SetConfigParam[] calldata _params) external override onlyEndpoint {
        for (uint256 i = 0; i < _params.length; i++) {
            SetConfigParam calldata param = _params[i];
            // _assertSupportedEid(param.eid);
            if (param.configType == CONFIG_TYPE_ULN) {
                _setUlnConfig(param.eid, _oapp, abi.decode(param.config, (UlnConfig)));
            } else {
                revert LZ_ULN_InvalidConfigType(param.configType);
            }
        }
    }

    // ============================ External ===================================

    /// @dev dont need to check endpoint verifiable here to save gas, as it will reverts if not verifiable.
    function commitVerification(bytes calldata _packetHeader, bytes32 _payloadHash) external {
        _assertHeader(_packetHeader, localEid);

        // cache these values to save gas
        address receiver = _packetHeader.receiverB20();
        uint32 srcEid = _packetHeader.srcEid();

        UlnConfig memory config = getUlnConfig(receiver, srcEid);
        _verifyAndReclaimStorage(config, keccak256(_packetHeader), _payloadHash);

        Origin memory origin = Origin(srcEid, _packetHeader.sender(), _packetHeader.nonce());
        // endpoint will revert if nonce <= lazyInboundNonce
        ILayerZeroEndpointV2(endpoint).verify(origin, receiver, _payloadHash);
    }

    /// @dev for dvn to verify the payload
    function verify(bytes calldata _packetHeader, bytes32 _payloadHash, uint64 _confirmations) external {
        _verify(_packetHeader, _payloadHash, _confirmations);
    }

    // ============================ View ===================================

    function getConfig(uint32 _eid, address _oapp, uint32 _configType) external view override returns (bytes memory) {
        if (_configType == CONFIG_TYPE_ULN) {
            return abi.encode(getUlnConfig(_oapp, _eid));
        } else {
            revert LZ_ULN_InvalidConfigType(_configType);
        }
    }

    function isSupportedEid(uint32) external pure override returns (bool) {
        return true;
    }

    function version() external pure override returns (uint64 major, uint8 minor, uint8 endpointVersion) {
        return (3, 0, 2);
    }
}
