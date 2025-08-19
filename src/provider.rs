//! Alloy provider extensions.

use crate::chains::{
    arb::{NODE_INTERFACE_CONTRACT, NodeInterface},
    op::{GAS_PRICE_ORACLE_CONTRACT, GasPriceOracle},
};
use alloy::{
    eips::{eip1559::Eip1559Estimation, eip7702::SignedAuthorization},
    primitives::{Address, Bytes, ChainId, U256},
    providers::Provider,
    transports::{TransportErrorKind, TransportResult},
};

/// Extension trait for [`Provider`] adding helpers for interacting with rollups.
pub trait ProviderExt: Provider {
    /// Heuristically determines whether this chain is an OP rollup.
    fn is_optimism(&self) -> impl Future<Output = TransportResult<bool>> + Send {
        async move {
            let chain_id = self.get_chain_id().await.unwrap();
            if alloy_chains::Chain::from(chain_id).is_optimism() {
                Ok(true)
            } else {
                Ok(!self.get_code_at(GAS_PRICE_ORACLE_CONTRACT).await?.is_empty())
            }
        }
    }

    /// Heuristically determines whether this chain is an Arbitrum rollup.
    fn is_arbitrum(&self) -> impl Future<Output = TransportResult<bool>> + Send {
        async move {
            let chain_id = self.get_chain_id().await.unwrap();
            if alloy_chains::Chain::from(chain_id).is_arbitrum() {
                Ok(true)
            } else {
                Ok(!self.get_code_at(NODE_INTERFACE_CONTRACT).await?.is_empty())
            }
        }
    }

    /// Estimates L1 DA fee of an OP Stack rollup for a given encoded unsigned transaction by using
    /// [`OpL1FeeOracle`].
    fn estimate_l1_op_fee(
        &self,
        encoded_tx: Bytes,
    ) -> impl Future<Output = TransportResult<U256>> + Send
    where
        Self: Sized,
    {
        async move {
            GasPriceOracle::new(GAS_PRICE_ORACLE_CONTRACT, self)
                .getL1Fee(encoded_tx)
                .call()
                .await
                .map_err(TransportErrorKind::custom)
        }
    }

    /// Estimates L1 DA fee of an Arbitrum rollup for given transaction parameters by using
    /// [`NodeInterface`].
    fn estimate_l1_arb_fee(
        &self,
        chain_id: ChainId,
        to: Address,
        gas_limit: u64,
        fees: Eip1559Estimation,
        auth: Option<SignedAuthorization>,
        calldata: Bytes,
    ) -> impl Future<Output = TransportResult<U256>> + Send
    where
        Self: Sized,
    {
        async move {
            let contract = NodeInterface::new(NODE_INTERFACE_CONTRACT, self);
            let mut call = contract
                .gasEstimateL1Component(to, false, calldata)
                .chain_id(chain_id)
                .nonce(rand::random())
                .gas(gas_limit)
                .max_fee_per_gas(fees.max_fee_per_gas)
                .max_priority_fee_per_gas(fees.max_priority_fee_per_gas);

            // Note: Nitro implementation doesn't account for authorization list when constructing
            // the message to calculate compressed size from.
            //
            // https://github.com/OffchainLabs/nitro/blob/90570c4bd330bd23321b9e4ca9e41440ab544d2a/execution/nodeInterface/NodeInterface.go#L490-L515
            if let Some(auth) = auth {
                call = call.authorization_list(vec![auth]);
            }

            call.call()
                .await
                .map(|components| {
                    U256::from(components.l1BaseFeeEstimate)
                        * U256::from(components.gasEstimateForL1)
                })
                .map_err(TransportErrorKind::custom)
        }
    }
}

impl<T> ProviderExt for T where T: Provider {}
