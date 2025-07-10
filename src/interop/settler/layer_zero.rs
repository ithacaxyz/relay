use alloy::{
    primitives::{Address, B256, Bytes, U256},
    providers::{DynProvider, Provider},
    rpc::types::TransactionRequest,
    sol,
    sol_types::{SolCall, SolValue},
};
use async_trait::async_trait;
use std::collections::HashMap;
use tracing::error;

use super::Settler;
use crate::{error::RelayError, transactions::RelayTransaction};

sol! {
    interface ILayerZeroSettler {
        function executeSend(address sender, bytes32 settlementId, bytes calldata settlerContext)
            external
            payable;
    }

    struct MessagingParams {
        uint32 dstEid;
        bytes32 receiver;
        bytes message;
        bytes options;
        bool payInLzToken;
    }

    struct MessagingFee {
        uint256 nativeFee;
        uint256 lzTokenFee;
    }

    #[sol(rpc)]
    interface ILayerZeroEndpointV2 {
        function quote(MessagingParams calldata _params, address _sender) external view returns (MessagingFee memory);
    }
}

/// LayerZero settler implementation for cross-chain settlement attestation.
#[derive(Debug)]
pub struct LayerZeroSettler {
    endpoint_ids: HashMap<u64, u32>,
    endpoint_addresses: HashMap<u64, Address>,
    providers: HashMap<u64, DynProvider>,
    settler_address: Address,
}

impl LayerZeroSettler {
    /// Creates a new LayerZero settler with the given endpoint configurations.
    pub fn new(
        endpoint_ids: HashMap<u64, u32>,
        endpoint_addresses: HashMap<u64, Address>,
        providers: HashMap<u64, DynProvider>,
        settler_address: Address,
    ) -> Self {
        Self { endpoint_ids, endpoint_addresses, providers, settler_address }
    }

    /// Gets the LayerZero endpoint address for a given chain ID.
    pub fn get_endpoint_address(&self, chain_id: u64) -> Option<&Address> {
        self.endpoint_addresses.get(&chain_id)
    }
}

#[async_trait]
impl Settler for LayerZeroSettler {
    fn id(&self) -> &'static str {
        "layer_zero"
    }

    fn address(&self) -> Address {
        self.settler_address
    }

    async fn build_send_settlement(
        &self,
        settlement_id: B256,
        current_chain_id: u64,
        source_chains: Vec<u64>,
        settler_contract: Address,
    ) -> Result<Option<RelayTransaction>, RelayError> {
        let settler_context = self.encode_settler_context(source_chains.clone())?;

        // Get the provider and endpoint address for the current chain
        let provider = self
            .providers
            .get(&current_chain_id)
            .ok_or_else(|| RelayError::UnsupportedChain(current_chain_id))?;

        let endpoint_address = self
            .endpoint_addresses
            .get(&current_chain_id)
            .ok_or_else(|| RelayError::UnsupportedChain(current_chain_id))?;

        // Create endpoint contract instance
        let endpoint = ILayerZeroEndpointV2::new(*endpoint_address, provider);

        // Build all messaging params
        let all_params = source_chains
            .iter()
            .map(|source_chain_id| {
                // Get the endpoint ID for this source chain (dst_eid in the quote context)
                let dst_eid = self
                    .endpoint_ids
                    .get(source_chain_id)
                    .ok_or_else(|| RelayError::UnsupportedChain(*source_chain_id))?;

                // Build messaging params
                Ok(MessagingParams {
                    dstEid: *dst_eid,
                    receiver: B256::left_padding_from(settler_contract.as_slice()),
                    message: (settlement_id, settler_contract, U256::from(*source_chain_id))
                        .abi_encode()
                        .into(),
                    options: Bytes::new(),
                    payInLzToken: false,
                })
            })
            .collect::<Result<Vec<_>, RelayError>>()?;

        // Build dynamic multicall using fold
        let multicall_dynamic =
            all_params.iter().fold(provider.multicall().dynamic(), |multicall, params| {
                multicall.add_dynamic(endpoint.quote(params.clone(), settler_contract))
            });

        // Process results and sum native fees
        let native_lz_fee: U256 =
            multicall_dynamic.aggregate().await?.into_iter().map(|fee| fee.nativeFee).sum();

        let calldata = ILayerZeroSettler::executeSendCall {
            sender: settler_contract,
            settlementId: settlement_id,
            settlerContext: settler_context,
        }
        .abi_encode();

        // Create an internal transaction for the settlement with the calculated value
        // Estimate gas for the settlement transaction
        const SETTLEMENT_FALLBACK_GAS_LIMIT: u64 = 1_000_000;

        let gas_limit = if let Some(provider) = self.providers.get(&current_chain_id) {
            let tx_request = TransactionRequest {
                from: Some(Address::ZERO),
                to: Some(settler_contract.into()),
                value: Some(native_lz_fee),
                input: calldata.clone().into(),
                ..Default::default()
            };

            provider
                .estimate_gas(tx_request)
                .await
                .map(|estimated| {
                    // Add 20% buffer
                    estimated.saturating_mul(120).saturating_div(100)
                })
                .unwrap_or_else(|e| {
                    error!(
                        chain_id = current_chain_id,
                        settler_contract = ?settler_contract,
                        error = ?e,
                        "Failed to estimate gas for settlement transaction, using fallback"
                    );
                    SETTLEMENT_FALLBACK_GAS_LIMIT
                })
        } else {
            error!(
                chain_id = current_chain_id,
                "No provider available for gas estimation, using fallback"
            );
            SETTLEMENT_FALLBACK_GAS_LIMIT
        };

        let tx = RelayTransaction::new_internal_with_value(
            settler_contract,
            calldata,
            current_chain_id,
            gas_limit,
            native_lz_fee,
        );

        Ok(Some(tx))
    }

    fn encode_settler_context(&self, destination_chains: Vec<u64>) -> Result<Bytes, RelayError> {
        let endpoint_ids: Vec<u32> = destination_chains
            .into_iter()
            .map(|chain_id| {
                // Validate we have both endpoint ID and address for this chain
                if !self.endpoint_addresses.contains_key(&chain_id) {
                    return Err(RelayError::UnsupportedChain(chain_id));
                }

                self.endpoint_ids
                    .get(&chain_id)
                    .copied()
                    .ok_or_else(|| RelayError::UnsupportedChain(chain_id))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Encode the endpoint IDs as a dynamic array of uint32
        Ok(endpoint_ids.abi_encode().into())
    }
}
