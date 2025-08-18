//! Faucet service for distributing test tokens.

use crate::{
    chains::Chains,
    signers::DynSigner,
    types::{
        IERC20,
        rpc::{AddFaucetFundsParameters, AddFaucetFundsResponse},
    },
};
use alloy::{
    consensus::{SignableTransaction, TxEip1559},
    eips::Encodable2718,
    primitives::{Bytes, U256},
    providers::Provider,
    rpc::types::TransactionRequest,
    sol_types::SolCall,
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
        let AddFaucetFundsParameters { token_address, address, chain_id, value } = params;

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

        // check ETH balance of the faucet (ETH is used to mint tokens)
        let faucet_address_balance = provider.get_balance(faucet_address).await?;
        if faucet_address_balance <= U256::from(1e18) {
            error!("Insufficient faucet balance");
            return Ok(AddFaucetFundsResponse {
                transaction_hash: None,
                message: Some("Insufficient faucet balance".to_string()),
            });
        }

        let mut fee_tokens = chain.assets().fee_tokens();
        // Ensure deterministic token selection order by sorting by AssetUid
        fee_tokens.sort_by(|(a_uid, _), (b_uid, _)| a_uid.as_str().cmp(b_uid.as_str()));

        // if token_address is provided, use it if supported otherwise return an error
        // if not provided, use the first fee token
        let fee_token_address = match token_address {
            Some(token_address) => {
                if !fee_tokens.iter().any(|(_, d)| d.address == token_address) {
                    error!("Token address {} not supported for chain {}", token_address, chain_id);
                    return Ok(AddFaucetFundsResponse {
                        transaction_hash: None,
                        message: Some("Token address not supported".to_string()),
                    });
                }
                token_address
            }
            None => {
                // Prefer a non-native, non-interop ERC20 as default (TODO: is this a good default?)
                if let Some((_, desc)) = fee_tokens
                    .iter()
                    .find(|(_, d)| d.address != alloy::primitives::Address::ZERO && !d.interop)
                {
                    desc.address
                } else if let Some((_, desc)) =
                    fee_tokens.iter().find(|(_, d)| d.address != alloy::primitives::Address::ZERO)
                {
                    desc.address
                } else {
                    fee_tokens.first().map(|(_, d)| d.address).ok_or_else(|| {
                        eyre::eyre!("No fee tokens configured for chain {}", chain_id)
                    })?
                }
            }
        };

        // Acquire lock to prevent concurrent transactions from the same faucet
        let _guard = self.lock.lock().await;

        let calldata: Bytes = IERC20::mintCall { recipient: address, value }.abi_encode().into();
        let gas_limit = provider
            .estimate_gas(
                TransactionRequest::default()
                    .to(fee_token_address)
                    .from(faucet_address)
                    .input(calldata.clone().into()),
            )
            .await?;

        let fees = provider.estimate_eip1559_fees().await?;
        let chain_id = provider.get_chain_id().await?;
        let nonce = provider.get_transaction_count(faucet_address).pending().await?;

        let mut tx = TxEip1559 {
            chain_id,
            nonce,
            to: fee_token_address.into(),
            gas_limit,
            max_fee_per_gas: fees.max_fee_per_gas,
            max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
            input: calldata,
            ..Default::default()
        };
        let signature = self.faucet_signer.sign_transaction(&mut tx).await?;
        let signed = tx.into_signed(signature);

        let tx_receipt =
            provider.send_raw_transaction(&signed.encoded_2718()).await?.get_receipt().await?;

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
