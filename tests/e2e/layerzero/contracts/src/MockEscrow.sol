// SPDX-License-Identifier: MIT
pragma solidity ^0.8.22;

import { OApp, MessagingFee } from "@layerzerolabs/oapp-evm/contracts/oapp/OApp.sol";
import { Origin } from "@layerzerolabs/lz-evm-protocol-v2/contracts/interfaces/ILayerZeroEndpointV2.sol";
import { OAppOptionsType3 } from "@layerzerolabs/oapp-evm/contracts/oapp/libs/OAppOptionsType3.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { SafeTransferLib } from "solady/utils/SafeTransferLib.sol";

contract MockEscrow is OApp, OAppOptionsType3 {
    using SafeTransferLib for address;
    
    // Locked balances per token per user
    mapping(address => mapping(address => uint256)) public lockedBalances;
    
    // Message type for cross-chain token transfers
    uint16 public constant TRANSFER = 1;
    
    struct CrossChainTransfer {
        address token;
        address from;
        address to;
        uint256 amount;
        uint32 srcEid;
    }
    
    event TokensLocked(address indexed token, address indexed from, uint256 amount, uint32 dstEid, address recipient);
    event TokensReleased(address indexed token, address indexed to, uint256 amount, uint32 srcEid);
    
    constructor(address _endpoint, address _owner) OApp(_endpoint, _owner) Ownable(_owner) {}
    
    function lockTokens(
        address _token,
        uint256 _amount,
        uint32 _dstEid,
        address _recipient,
        bytes calldata _options
    ) external payable {
        // Transfer tokens to escrow
        SafeTransferLib.safeTransferFrom(_token, msg.sender, address(this), _amount);
        lockedBalances[_token][msg.sender] += _amount;
        
        // Prepare cross-chain message
        CrossChainTransfer memory transfer = CrossChainTransfer({
            token: _token,
            from: msg.sender,
            to: _recipient,
            amount: _amount,
            srcEid: endpoint.eid()
        });
        
        bytes memory message = abi.encode(transfer);
        
        // Send via LayerZero
        _lzSend(
            _dstEid,
            message,
            combineOptions(_dstEid, TRANSFER, _options),
            MessagingFee(msg.value, 0),
            payable(msg.sender)
        );
        
        emit TokensLocked(_token, msg.sender, _amount, _dstEid, _recipient);
    }
    
    function _lzReceive(
        Origin calldata _origin,
        bytes32 /*_guid*/,
        bytes calldata _message,
        address /*_executor*/,
        bytes calldata /*_extraData*/
    ) internal override {
        // Decode the transfer details
        CrossChainTransfer memory transfer = abi.decode(_message, (CrossChainTransfer));
        
        // Release tokens to recipient
        SafeTransferLib.safeTransfer(transfer.token, transfer.to, transfer.amount);
        
        emit TokensReleased(transfer.token, transfer.to, transfer.amount, _origin.srcEid);
    }
    
    function quoteLayerZeroFee(
        uint32 _dstEid,
        address _token,
        uint256 _amount,
        address _recipient,
        bytes calldata _options
    ) external view returns (MessagingFee memory fee) {
        CrossChainTransfer memory transfer = CrossChainTransfer({
            token: _token,
            from: msg.sender,
            to: _recipient,
            amount: _amount,
            srcEid: endpoint.eid()
        });
        
        bytes memory message = abi.encode(transfer);
        fee = _quote(_dstEid, message, combineOptions(_dstEid, TRANSFER, _options), false);
    }
}