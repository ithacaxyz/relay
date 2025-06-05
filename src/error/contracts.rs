alloy::sol! {
    /// Common contract errors.
    #[sol(rpc)]
    #[derive(Debug)]
    contract ContractErrors {
        // OpenZeppelin core
        error OwnableUnauthorizedAccount(address account);
        error OwnableInvalidOwner(address owner);
        error AccessControlUnauthorizedAccount(address account, bytes32 neededRole);
        error AccessControlBadConfirmation();
        error ReentrancyGuardReentrantCall();
        error Reentrancy();
        error Paused();
        error NotPaused();

        // Generic utilities
        error AddressEmptyCode(address target);
        error ZeroAddress();
        error InvalidSignature();
        error DeadlineExpired(uint256 deadline, uint256 timestamp);

        // OpenZeppelin ERC-20 (ERC-6093)
        error ERC20InsufficientBalance(address sender, uint256 balance, uint256 needed);
        error ERC20InsufficientAllowance(address spender, uint256 allowance, uint256 needed);
        error ERC20InvalidSender(address sender);
        error ERC20InvalidReceiver(address receiver);
        error ERC20InvalidApprover(address approver);
        error ERC20InvalidSpender(address spender);

        // OpenZeppelin ERC-721 (ERC-6093 + extras)
        error ERC721InvalidOwner(address owner);
        error ERC721NonexistentToken(uint256 tokenId);
        error ERC721IncorrectOwner(address sender, uint256 tokenId, address owner);
        error ERC721InvalidSender(address sender);
        error ERC721InvalidReceiver(address receiver);
        error ERC721InsufficientApproval(address operator, uint256 tokenId);
        error ERC721InvalidApprover(address approver);
        error ERC721InvalidOperator(address operator);
        error ERC721ExceededMaxBatchMint(uint256 batchSize, uint256 maxBatch);
        error ERC721ForbiddenBatchMint();
        error ERC721ForbiddenMint();
        error ERC721ForbiddenBatchBurn();

        // OpenZeppelin ERC-1155 (ERC-6093)
        error ERC1155InsufficientBalance(address sender, uint256 balance, uint256 needed, uint256 id);
        error ERC1155InvalidSender(address sender);
        error ERC1155InvalidReceiver(address receiver);
        error ERC1155MissingApprovalForAll(address operator, address owner);
        error ERC1155InvalidApprover(address approver);
        error ERC1155InvalidOperator(address operator);
        error ERC1155InvalidArrayLength(uint256 idsLength, uint256 valuesLength);

        // OpenZeppelin ERC-4626 vault limits
        error ERC4626ExceededMaxDeposit(address receiver, uint256 assets, uint256 max);
        error ERC4626ExceededMaxMint(address receiver, uint256 shares, uint256 max);
        error ERC4626ExceededMaxWithdraw(address owner, uint256 assets, uint256 max);
        error ERC4626ExceededMaxRedeem(address owner, uint256 shares, uint256 max);

        // OpenZeppelin SafeERC20 wrappers
        error SafeERC20FailedOperation(address token);
        error SafeERC20FailedDecreaseAllowance(address spender, uint256 currentAllowance, uint256 requestedDecrease);

        // OpenZeppelin ERC-2981 royalties
        error ERC2981InvalidDefaultRoyalty(uint256 numerator, uint256 denominator);
        error ERC2981InvalidDefaultRoyaltyReceiver(address receiver);
        error ERC2981InvalidTokenRoyalty(uint256 tokenId, uint256 numerator, uint256 denominator);

        // Solady SafeTransferLib
        error ETHTransferFailed();
        error TransferFailed();
        error TransferFromFailed();
        error ApproveFailed();

        // Solady ERC-20 extras
        error AllowanceOverflow();
        error AllowanceUnderflow();
        error InsufficientAllowance();
        error InsufficientBalance();
        error TotalSupplyOverflow();
        error PermitExpired();
        error Permit2AllowanceIsFixedAtInfinity();
        error InvalidPermit();

        // Solady ERC-721 extras
        error NotOwnerNorApproved();
        error TokenDoesNotExist();
        error TokenAlreadyExists();
        error BalanceQueryForZeroAddress();
        error TransferToZeroAddress();
        error TransferFromIncorrectOwner();
        error AccountBalanceOverflow();
        error TransferToNonERC721ReceiverImplementer();

        // Solady ERC-1155 helpers
        error ArrayLengthsMismatch();
        error TransferToNonERC1155ReceiverImplementer();

        // Solady auth & role mix-ins
        error Unauthorized();
        error InvalidRole();
        error EnumerableRolesUnauthorized();
        error OperationNotSupported();
        error SelfOwnDetected();

        // Solady deployment & init
        error InvalidInitialization();
        error NotInitializing();
        error DeploymentFailed();
        error SaltDoesNotStartWith();

        // Solady math guards
        error FactorialOverflow();
        error RPowOverflow();
    }
}
