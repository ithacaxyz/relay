use super::Settler;
use crate::{error::RelayError, transactions::RelayTransaction};
use alloy::primitives::{Address, B256, Bytes};
use async_trait::async_trait;

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
        _current_chain_id: u64,
        _source_chains: Vec<u64>,
        _settler_contract: Address,
    ) -> Result<Option<RelayTransaction>, RelayError> {
        // Simple settler doesn't need to send settlement transactions
        // The settlement is handled directly during intent execution
        Ok(None)
    }

    fn encode_settler_context(&self, _destination_chains: Vec<u64>) -> Result<Bytes, RelayError> {
        // Simple settler doesn't need any context
        Ok(Bytes::default())
    }
}
