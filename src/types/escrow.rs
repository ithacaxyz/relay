//! Escrow contract types and interfaces.
//!
//! This module defines the escrow system used for cross-chain intents,
//! where funds are locked in escrow until settlement or refund conditions are met.

use alloy::{
    primitives::{B256, keccak256},
    sol,
    sol_types::SolValue,
};
use serde::{Deserialize, Serialize};

sol! {
    /// Represents the current state of an escrow.
    #[derive(Debug, PartialEq, Eq)]
    enum EscrowStatus {
        /// Default null status - escrow does not exist.
        NULL,
        /// Escrow has been created and funds are locked.
        CREATED,
        /// Escrow has been refunded to the depositor.
        REFUND_DEPOSIT,
        /// Escrow has been refunded to the recipient.
        REFUND_RECIPIENT,
        /// Finalized.
        FINALIZED
    }

    /// Represents an escrow entry with all necessary metadata for cross-chain settlement.
    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Escrow {
        /// Random salt for escrow uniqueness.
        bytes12 salt;
        /// Address that deposited the funds.
        address depositor;
        /// Address that will receive funds upon settlement.
        address recipient;
        /// Token address (or zero address for native token).
        address token;
        /// Amount of tokens locked in escrow.
        uint256 escrowAmount;
        /// Amount to refund if escrow is not settled.
        uint256 refundAmount;
        /// Timestamp after which the escrow can be refunded.
        uint256 refundTimestamp;
        /// Address of the settler contract responsible for attestation.
        address settler;
        /// Address of the sender on the output chain (typically orchestrator).
        address sender;
        /// Unique identifier linking this escrow to a settlement (typically the output intent hash).
        bytes32 settlementId;
        /// Chain ID where the sender resides.
        uint256 senderChainId;
    }

    #[sol(rpc)]
    #[derive(Debug)]
    contract IEscrow {
        /// Emitted when an escrow is created.
        event EscrowCreated(bytes32 escrowId);

        /// Emitted when an escrow is refunded.
        event EscrowRefunded(bytes32 escrowId);

        /// Emitted when an escrow is settled.
        event EscrowSettled(bytes32 escrowId);

        /// Invalid escrow status for the requested operation.
        error InvalidStatus();

        /// Refund period has expired.
        error RefundExpired();

        /// Settlement is not ready to be processed.
        error SettlementNotReady();

        /// Creates one or more escrows, locking funds until settlement or refund.
        ///
        /// Accounts call this function to escrow funds for cross-chain intents.
        /// For native token escrows, the total value must be sent with the transaction.
        /// For ERC20 tokens, the contract must have approval to transfer the tokens.
        ///
        /// # Arguments
        /// * `_escrows` - Array of Escrow structs defining the escrows to create
        function escrow(Escrow[] memory _escrows) external payable;

        /// Refunds one or more escrows back to their respective depositors.
        ///
        /// Can only be called after the refund timestamp has passed.
        /// Escrows must be in CREATED status to be refunded.
        ///
        /// # Arguments
        /// * `escrowIds` - Array of escrow IDs to refund
        function refund(bytes32[] calldata escrowIds) external;

        /// Settles one or more escrows, transferring funds to their recipients.
        ///
        /// Settlement requires proper attestation from the settler contract.
        /// Escrows must be in CREATED status to be settled.
        ///
        /// # Arguments
        /// * `escrowIds` - Array of escrow IDs to settle
        function settle(bytes32[] calldata escrowIds) external;
    }
}

impl Escrow {
    /// Calculates the escrow ID from the escrow parameters.
    ///
    /// The escrow ID is calculated as keccak256(abi.encode(escrow))
    pub fn calculate_id(&self) -> B256 {
        keccak256(self.abi_encode())
    }
}
