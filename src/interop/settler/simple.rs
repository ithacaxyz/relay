use super::{SettlementError, Settler};
use crate::transactions::RelayTransaction;
use alloy::{
    primitives::{Address, B256, Bytes, ChainId, U256},
    sol_types::SolValue,
};
use async_trait::async_trait;
use itertools::Itertools;

/// A simple settler implementation that does not require cross-chain attestation.
/// This is useful for testing and development environments.
#[derive(Debug)]
pub struct SimpleSettler {
    /// The address of the settler contract
    settler_address: Address,
}

impl SimpleSettler {
    /// Creates a new simple settler instance
    pub fn new(settler_address: Address) -> Self {
        Self { settler_address }
    }
}

#[async_trait]
impl Settler for SimpleSettler {
    fn id(&self) -> &'static str {
        "simple"
    }

    fn address(&self) -> Address {
        self.settler_address
    }

    async fn build_send_settlement(
        &self,
        _settlement_id: B256,
        _current_chain_id: ChainId,
        _source_chains: Vec<ChainId>,
        _orchestrator: Address,
    ) -> Result<Option<RelayTransaction>, SettlementError> {
        // Simple settler doesn't need to send settlement transactions
        // The settlement is handled directly during intent execution
        Ok(None)
    }

    fn encode_settler_context(&self, chains: Vec<ChainId>) -> Result<Bytes, SettlementError> {
        // Encode the input chain IDs for the settler context
        let input_chain_ids: Vec<U256> =
            chains.iter().sorted().map(|chain_id| U256::from(*chain_id)).collect();

        // Simple settler doesn't need any context
        Ok(input_chain_ids.abi_encode().into())
    }
}
