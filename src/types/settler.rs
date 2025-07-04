//! Settler contract types and interfaces.
//!
//! The settler contract handles cross-chain attestations for multichain intents,
//! enabling trust between different chains during settlement.

use alloy::sol;

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    contract Settler {
        /// Emitted when a settlementId is sent to one or more chains.
        event Sent(address indexed sender, bytes32 indexed settlementId, uint256 receiverChainId);

        /// Allows anyone to attest to any settlementId, on all the input chains.
        /// Input chain readers can choose which attestations they want to trust.
        ///
        /// # Arguments
        /// * `settlementId` - The ID of the settlement to attest to
        /// * `settlerContext` - Encoded context data that the settler can decode (e.g., array of input chains)
        function send(bytes32 settlementId, bytes calldata settlerContext) external payable;

        /// Write the settlement status for a specific sender and chain.
        /// Only the owner can call this function.
        ///
        /// # Arguments
        /// * `sender` - The address of the sender
        /// * `settlementId` - The ID of the settlement
        /// * `chainId` - The chain ID
        function write(address sender, bytes32 settlementId, uint256 chainId) external;

        /// Check if an attester from a particular output chain has attested to the settlementId.
        /// For our case, the attester is the orchestrator.
        /// And the settlementId is the root of the merkle tree which is signed by the user.
        ///
        /// # Arguments
        /// * `settlementId` - The ID of the settlement to check
        /// * `attester` - The address of the attester
        /// * `chainId` - The chain ID to check
        function read(bytes32 settlementId, address attester, uint256 chainId)
            external
            view
            returns (bool isSettled);
    }
}
