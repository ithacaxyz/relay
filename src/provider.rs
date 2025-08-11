//! Alloy provider extensions and caching wrappers.

use crate::op::{OP_FEE_ORACLE_CONTRACT, OpL1FeeOracle};
use alloy::{
    primitives::{Bytes, U256},
    providers::Provider,
    transports::{TransportErrorKind, TransportResult},
};

/// Extension trait for [`Provider`] adding helpers for interacting with OP rollups.
pub trait ProviderExt: Provider {
    /// Heuristically determines whether this chain is an OP rollup.
    fn is_optimism(&self) -> impl Future<Output = TransportResult<bool>> + Send {
        async move {
            let chain_id = self.get_chain_id().await?;
            if alloy_chains::Chain::from(chain_id).is_optimism() {
                Ok(true)
            } else {
                Ok(!self.get_code_at(OP_FEE_ORACLE_CONTRACT).await?.is_empty())
            }
        }
    }

    /// Estimates L1 DA fee for a given encoded transaction by using [`OpL1FeeOracle`].
    fn estimate_l1_fee(
        &self,
        encoded_tx: Bytes,
    ) -> impl Future<Output = TransportResult<U256>> + Send
    where
        Self: Sized,
    {
        async move {
            OpL1FeeOracle::new(OP_FEE_ORACLE_CONTRACT, self)
                .getL1Fee(encoded_tx)
                .call()
                .await
                .map_err(TransportErrorKind::custom)
        }
    }
}

impl<T> ProviderExt for T where T: Provider {}
