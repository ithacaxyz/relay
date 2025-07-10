use super::{SettlementError, Settler};
use crate::transactions::RelayTransaction;
use alloy::{
    primitives::{Address, B256, Bytes, ChainId, U256},
    providers::{DynProvider, Provider},
    rpc::types::{TransactionRequest, state::AccountOverride},
    sol,
    sol_types::{SolCall, SolValue},
};
use async_trait::async_trait;
use std::collections::HashMap;
use tracing::instrument;

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
    ///
    /// # Arguments
    ///
    /// * `endpoint_ids` - Mapping of chain ID to LayerZero endpoint ID
    /// * `endpoint_addresses` - Mapping of chain ID to LayerZero endpoint address
    /// * `providers` - Mapping of chain ID to provider instances
    /// * `settler_address` - The address of the LayerZero settler contract
    pub fn new(
        endpoint_ids: HashMap<ChainId, u32>,
        endpoint_addresses: HashMap<ChainId, Address>,
        providers: HashMap<ChainId, DynProvider>,
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

    #[instrument(skip(self), fields(settler_id = %self.id()))]
    async fn build_send_settlement(
        &self,
        settlement_id: B256,
        current_chain_id: u64,
        source_chains: Vec<u64>,
        orchestrator: Address,
    ) -> Result<Option<RelayTransaction>, SettlementError> {
        let settler_context = self.encode_settler_context(source_chains.clone())?;

        // Get the provider and endpoint address for the current chain
        let provider = self
            .providers
            .get(&current_chain_id)
            .ok_or_else(|| SettlementError::UnsupportedChain(current_chain_id))?;

        let endpoint_address = self
            .endpoint_addresses
            .get(&current_chain_id)
            .ok_or_else(|| SettlementError::UnsupportedChain(current_chain_id))?;

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
                    .ok_or_else(|| SettlementError::UnsupportedChain(*source_chain_id))?;

                // Build messaging params
                Ok(MessagingParams {
                    dstEid: *dst_eid,
                    receiver: B256::left_padding_from(self.settler_address.as_slice()),
                    message: (settlement_id, self.settler_address, U256::from(*source_chain_id))
                        .abi_encode()
                        .into(),
                    options: Bytes::new(),
                    payInLzToken: false,
                })
            })
            .collect::<Result<Vec<_>, SettlementError>>()?;

        // Quote for all chain fees.
        let multicall =
            all_params.iter().fold(provider.multicall().dynamic(), |multicall, params| {
                multicall.add_dynamic(endpoint.quote(params.clone(), self.settler_address))
            });

        let native_lz_fee: U256 =
            multicall.aggregate().await?.into_iter().map(|fee| fee.nativeFee).sum();

        let calldata = ILayerZeroSettler::executeSendCall {
            sender: orchestrator,
            settlementId: settlement_id,
            settlerContext: settler_context,
        }
        .abi_encode();

        // Create an internal transaction for the settlement with the calculated value
        // Estimate gas for the settlement transaction
        let provider = self
            .providers
            .get(&current_chain_id)
            .ok_or_else(|| SettlementError::UnsupportedChain(current_chain_id))?;

        let from = Address::random();
        let tx_request = TransactionRequest {
            from: Some(from),
            to: Some(self.settler_address.into()),
            value: Some(native_lz_fee),
            input: calldata.clone().into(),
            ..Default::default()
        };

        let gas_limit = provider
            .estimate_gas(tx_request)
            .account_override(from, AccountOverride::default().with_balance(U256::MAX))
            .await?;

        // Add 20% buffer to the gas estimate
        let gas_limit = gas_limit.saturating_mul(120).saturating_div(100);

        let tx = RelayTransaction::new_internal_with_value(
            self.settler_address,
            calldata,
            current_chain_id,
            gas_limit,
            native_lz_fee,
        );

        Ok(Some(tx))
    }

    fn encode_settler_context(
        &self,
        destination_chains: Vec<u64>,
    ) -> Result<Bytes, SettlementError> {
        let endpoint_ids: Vec<u32> = destination_chains
            .into_iter()
            .map(|chain_id| {
                // Validate we have both endpoint ID and address for this chain
                if !self.endpoint_addresses.contains_key(&chain_id) {
                    return Err(SettlementError::UnsupportedChain(chain_id));
                }

                self.endpoint_ids
                    .get(&chain_id)
                    .copied()
                    .ok_or_else(|| SettlementError::UnsupportedChain(chain_id))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // Encode the endpoint IDs as a dynamic array of uint32
        Ok(endpoint_ids.abi_encode().into())
    }
}
