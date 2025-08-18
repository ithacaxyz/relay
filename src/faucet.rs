//! Faucet service for distributing test tokens.

use crate::{
    chains::Chains,
    signers::DynSigner,
    transactions::RelayTransaction,
    types::{
        IERC20,
        rpc::{AddFaucetFundsParameters, AddFaucetFundsResponse},
    },
};
use alloy::{
    primitives::{Bytes, TxKind, U256},
    providers::Provider,
    rpc::types::TransactionRequest,
    sol_types::SolCall,
};
use eyre::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, instrument, warn};

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
        let AddFaucetFundsParameters { token_address, address, chain_id, value } = params;

        info!(
            "Processing faucet request for {} on chain {} with amount {}",
            address, chain_id, value
        );

        let chain = self
            .chains
            .get(chain_id)
            .ok_or_else(|| eyre::eyre!("Chain {} not supported", chain_id))?;

        // Disallow faucet usage on mainnet chains
        if alloy_chains::Chain::from(chain_id).named().is_some_and(|c| !c.is_testnet()) {
            warn!("Faucet request blocked on mainnet (chain {chain_id})");
            return Ok(AddFaucetFundsResponse {
                transaction_hash: None,
                message: Some("Faucet disabled on mainnet".to_string()),
            });
        }

        let provider = chain.provider();
        let faucet_address = self.faucet_signer.address();

        let fee_tokens = chain.assets().fee_tokens();

        // check if the token is supported
        if !fee_tokens.iter().any(|(_, d)| d.address == token_address) {
            error!("Token address {} not supported for chain {}", token_address, chain_id);
            return Ok(AddFaucetFundsResponse {
                transaction_hash: None,
                message: Some("Token address not supported".to_string()),
            });
        }

        // Acquire lock to prevent concurrent transactions from the same faucet
        let _guard = self.lock.lock().await;

        let calldata: Bytes = IERC20::mintCall { recipient: address, value }.abi_encode().into();
        let gas_limit = match provider
            .estimate_gas(
                TransactionRequest::default()
                    .to(token_address)
                    .from(faucet_address)
                    .input(calldata.clone().into()),
            )
            .await
        {
            Ok(g) => g,
            Err(e) => {
                error!(
                    "Faucet mint not supported for token {token_address} on chain {chain_id}: {e}"
                );
                return Ok(AddFaucetFundsResponse {
                    transaction_hash: None,
                    message: Some("Token address not supported".to_string()),
                });
            }
        };

        // Build an internal transaction and route via TransactionService, targeting faucet signer
        let chain_id = provider.get_chain_id().await?;
        let relay_tx = RelayTransaction::new_internal_from(
            TxKind::Call(token_address),
            calldata,
            chain_id,
            gas_limit,
            U256::ZERO,
            Some(faucet_address),
        );

        let handle = self
            .chains
            .get(chain_id)
            .ok_or_else(|| eyre::eyre!("Chain {} not supported", chain_id))?
            .transactions()
            .clone();

        // Enqueue and wait for confirmation
        let _ = handle.send_transaction(relay_tx.clone()).await?;
        let status = handle.wait_for_tx(relay_tx.id).await?;

        if !status.is_confirmed() {
            error!("Faucet funding failed");
            return Ok(AddFaucetFundsResponse {
                transaction_hash: status.tx_hash(),
                message: Some("Faucet funding failed".to_string()),
            });
        }

        Ok(AddFaucetFundsResponse {
            transaction_hash: status.tx_hash(),
            message: Some("Faucet funding successful".to_string()),
        })
    }
}
