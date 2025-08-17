//! Faucet service for distributing test tokens.

use crate::{
    chains::Chains,
    signers::DynSigner,
    types::{
        IERC20,
        rpc::{AddFaucetFundsParameters, AddFaucetFundsResponse},
    },
};
use eyre::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, instrument};

/// Faucet service for distributing test tokens.
#[derive(Debug, Clone)]
pub struct FaucetService {
    /// The signer used for faucet operations.
    faucet_signer: DynSigner,
    /// The chains supported by the relay.
    chains: Arc<Chains>,
    /// Mutex to synchronize faucet transactions.
    lock: Arc<Mutex<()>>,
}

impl FaucetService {
    /// Create a new faucet service.
    pub fn new(faucet_signer: DynSigner, chains: Arc<Chains>) -> Self {
        Self { faucet_signer, chains, lock: Arc::new(Mutex::new(())) }
    }

    /// Add faucet funds to an address on a specific chain.
    #[instrument(skip(self), fields(address = %params.address, chain_id = %params.chain_id, value = %params.value))]
    pub async fn add_faucet_funds(
        &self,
        params: AddFaucetFundsParameters,
    ) -> Result<AddFaucetFundsResponse> {
        let AddFaucetFundsParameters { address, chain_id, value } = params;

        info!(
            "Processing faucet request for {} on chain {} with amount {}",
            address, chain_id, value
        );

        let chain = self
            .chains
            .get(chain_id)
            .ok_or_else(|| eyre::eyre!("Chain {} not supported", chain_id))?;

        let provider = chain.provider();
        let faucet_address = self.faucet_signer.address();

        let fee_token_address =
            chain
                .assets()
                .fee_tokens()
                .first()
                .map(|(_, desc)| desc.address)
                .ok_or_else(|| eyre::eyre!("No fee token found for chain {}", chain_id))?;

        // Acquire lock to prevent concurrent transactions from the same faucet
        let _guard = self.lock.lock().await;

        let fee_token = IERC20::IERC20Instance::new(fee_token_address, provider.clone());

        let faucet_address_balance = fee_token.balanceOf(faucet_address).call().await?;
        if faucet_address_balance <= value {
            error!("Insufficient faucet balance");
            return Ok(AddFaucetFundsResponse {
                transaction_hash: None,
                message: Some("Insufficient faucet balance".to_string()),
            });
        }

        let pending_tx = fee_token.mint(address, value).from(faucet_address).send().await?;
        let tx_receipt = pending_tx.get_receipt().await?;

        if !tx_receipt.status() {
            error!("Faucet funding failed");
            return Ok(AddFaucetFundsResponse {
                transaction_hash: None,
                message: Some("Faucet funding failed".to_string()),
            });
        }

        Ok(AddFaucetFundsResponse {
            transaction_hash: Some(tx_receipt.transaction_hash),
            message: Some("Faucet funding successful".to_string()),
        })
    }
}
