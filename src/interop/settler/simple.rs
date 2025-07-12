use super::{SettlementError, Settler, VerificationResult};
use crate::transactions::{RelayTransaction, interop::InteropBundle};
use alloy::{
    primitives::{Address, B256, Bytes, ChainId, U256},
    sol_types::SolValue,
};
use async_trait::async_trait;
use itertools::Itertools;
use std::time::Duration;

/// A simple settler implementation that does not require cross-chain attestation.
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

    async fn build_execute_send_transaction(
        &self,
        _settlement_id: B256,
        _current_chain_id: ChainId,
        _source_chains: Vec<ChainId>,
        _orchestrator: Address,
    ) -> Result<Option<RelayTransaction>, SettlementError> {
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

    async fn wait_for_verifications(
        &self,
        _bundle: &InteropBundle,
        _timeout: Duration,
    ) -> Result<VerificationResult, SettlementError> {
        // Simple settler doesn't need verification, always return success
        Ok(VerificationResult { verified_packets: vec![], failed_packets: vec![] })
    }

    async fn build_execute_receive_transactions(
        &self,
        _bundle: &InteropBundle,
    ) -> Result<Vec<RelayTransaction>, SettlementError> {
        // currently broken, since the contract itself requires these transaction coming from a
        // single owner, but we use random signers.
        Ok(vec![])
    }
}
