//! Faucet service for distributing test tokens.

use alloy::providers::Provider;
use eyre::Result;
use std::sync::Arc;
use tracing::{error, info, instrument};

use crate::{
    chains::Chains,
    signers::DynSigner,
    types::rpc::{AddFaucetFundsParameters, AddFaucetFundsResponse},
};

/// Faucet service for distributing test tokens.
#[derive(Debug, Clone)]
pub struct FaucetService {
    /// The signer used for faucet operations.
    faucet_signer: DynSigner,
    /// The chains supported by the relay.
    chains: Arc<Chains>,
}

impl FaucetService {
    /// Create a new faucet service.
    pub fn new(faucet_signer: DynSigner, chains: Arc<Chains>) -> Self {
        Self {
            faucet_signer,
            chains,
        }
    }

    /// Add faucet funds to an address on a specific chain.
    #[instrument(skip(self), fields(address = %params.address, chain_id = %params.chain_id, value = %params.value))]
    pub async fn add_faucet_funds(
        &self,
        params: AddFaucetFundsParameters,
    ) -> Result<AddFaucetFundsResponse> {
        let AddFaucetFundsParameters {
            address,
            chain_id,
            value,
        } = params;

        info!(
            "Processing faucet request for {} on chain {} with amount {}",
            address, chain_id, value
        );

        // Get the chain
        let chain = self
            .chains
            .get(chain_id)
            .ok_or_else(|| eyre::eyre!("Chain {} not supported", chain_id))?;

        // Get the provider for this chain
        let provider = chain.provider();

        // Get faucet address
        let faucet_address = self.faucet_signer.address();

        // Check faucet balance
        let balance = provider.get_balance(faucet_address).await?;
        if balance < value {
            error!(
                "Insufficient faucet balance. Required: {}, Available: {}",
                value, balance
            );
            return Ok(AddFaucetFundsResponse {
                transaction_hash: None,
                success: false,
                message: Some(format!(
                    "Insufficient faucet balance. Required: {}, Available: {}",
                    value, balance
                )),
            });
        }

        // TODO: Implement the actual transaction sending logic
        // This would involve:
        // 1. Building a transaction to send funds from faucet to the target address
        // 2. Signing the transaction with the faucet_signer
        // 3. Sending the transaction to the chain
        // 4. Waiting for confirmation
        // 5. Returning the transaction hash

        // For now, return a placeholder response
        Ok(AddFaucetFundsResponse {
            transaction_hash: None,
            success: false,
            message: Some("Faucet funding implementation pending".to_string()),
        })
    }
}