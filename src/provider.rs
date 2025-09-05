//! Alloy provider extensions.

use crate::{
    estimation::{
        arb::{ARB_NODE_INTERFACE_ADDRESS, ArbNodeInterface},
        op::{OP_GAS_PRICE_ORACLE_ADDRESS, OpGasPriceOracle},
    },
    types::IERC20,
};
use alloy::{
    eips::{eip1559::Eip1559Estimation, eip7702::SignedAuthorization},
    primitives::{Address, Bytes, ChainId, U256},
    providers::Provider,
    transports::{TransportErrorKind, TransportResult},
};

/// Nitro implementation doesn't account for authorization list when
/// constructing the message to calculate compressed size from.
/// Because of this, we add a 5% safety margin to the gas estimate.
///
/// https://github.com/OffchainLabs/nitro/blob/90570c4bd330bd23321b9e4ca9e41440ab544d2a/execution/nodeInterface/NodeInterface.go#L490-L515
const ARB_GAS_ESTIMATE_7702_MARGIN_PERCENT: u64 = 5;

/// Extension trait for [`Provider`] adding helpers for interacting with rollups.
pub trait ProviderExt: Provider {
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
            OpGasPriceOracle::new(OP_GAS_PRICE_ORACLE_ADDRESS, self)
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
            let contract = ArbNodeInterface::new(ARB_NODE_INTERFACE_ADDRESS, self);

            contract
                .gasEstimateL1Component(to, false, calldata)
                .chain_id(chain_id)
                .nonce(rand::random())
                .gas(gas_limit)
                .max_fee_per_gas(fees.max_fee_per_gas)
                .max_priority_fee_per_gas(fees.max_priority_fee_per_gas)
                .call()
                .await
                .map(|components| {
                    let mut gas_estimate = components.gasEstimateForL1;

                    if auth.is_some() {
                        gas_estimate =
                            gas_estimate * (100 + ARB_GAS_ESTIMATE_7702_MARGIN_PERCENT) / 100;
                    }

                    U256::from(components.l1BaseFeeEstimate) * U256::from(gas_estimate)
                })
                .map_err(TransportErrorKind::custom)
        }
    }

    /// Gets the decimals of a token.
    fn get_token_decimals(
        &self,
        address: Address,
    ) -> impl Future<Output = Result<u8, alloy::contract::Error>> + Send
    where
        Self: Sized,
    {
        async move { IERC20::new(address, self).decimals().call().await }
    }
}

impl<T> ProviderExt for T where T: Provider {}
