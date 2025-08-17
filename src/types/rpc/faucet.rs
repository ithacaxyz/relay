//! RPC faucet-related request and response types.

use alloy::primitives::{Address, ChainId, U256};
use serde::{Deserialize, Serialize};

/// Parameters for the `wallet_addFaucetFunds` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddFaucetFundsParameters {
    /// The address to send funds to.
    pub address: Address,
    /// The chain ID where the funds should be added.
    pub chain_id: ChainId,
    /// The amount of funds to add (in wei for native tokens).
    pub value: U256,
}

/// Response for the `wallet_addFaucetFunds` method.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AddFaucetFundsResponse {
    /// The transaction hash of the funding transaction.
    pub transaction_hash: Option<alloy::primitives::TxHash>,
    /// Success status of the operation.
    pub success: bool,
    /// Optional message providing details about the operation.
    pub message: Option<String>,
}
