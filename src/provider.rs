//! Alloy provider extensions.

use alloy::{
    primitives::{Address, U256, address},
    providers::Provider,
    sol,
    transports::{TransportErrorKind, TransportResult},
};
use op_alloy_flz::{NON_ZERO_BYTE_COST, tx_estimated_size_fjord};

/// Address of the L1Block contract.
pub const L1_BLOCK_CONTRACT: Address = address!("0x4200000000000000000000000000000000000015");

sol! {
    #[sol(rpc)]
    contract L1Block {
        uint256 public basefee;
        uint32 public blobBaseFeeScalar;
        uint32 public baseFeeScalar;
        uint256 public l1FeeOverhead;
        uint256 public l1FeeScalar;
        uint256 public blobBaseFee;
    }
}

/// Context fetched from OP L1Block contract.
#[derive(Debug, Clone, Copy)]
pub struct L1BlockFees {
    /// Base fee of L1 block.
    base_fee: U256,
    /// Value applied to the base fee when calculating the L1 fee.
    base_fee_scalar: U256,
    /// Base fee per blob gas of L1 block.
    blob_base_fee: U256,
    /// Value applied to the blob base fee when calculating the L1 fee.
    blob_base_fee_scalar: U256,
}

impl L1BlockFees {
    /// Calculates the L1 fee multiplier from both base fee and blob fee.
    pub fn l1_fee_scaled(&self) -> U256 {
        self.base_fee * self.base_fee_scalar * U256::from(NON_ZERO_BYTE_COST)
            + self.blob_base_fee * self.blob_base_fee_scalar
    }

    /// Estimates the L1 cost to be paid for the given transaction.
    pub fn estimate_l1_cost(&self, input: &[u8]) -> U256 {
        U256::from(tx_estimated_size_fjord(input))
            .saturating_mul(self.l1_fee_scaled())
            .wrapping_div(U256::from(1_000_000_000_000_u128))
    }
}

/// Extension trait for [`Provider`] adding helpers for interacting with OP rollups.
pub trait ProviderExt: Provider {
    /// Heuristically determines whether this chain is an OP rollup.
    fn is_optimism(&self) -> impl Future<Output = TransportResult<bool>> + Send {
        async move {
            let chain_id = self.get_chain_id().await.unwrap();
            if alloy_chains::Chain::from(chain_id).is_optimism() {
                Ok(true)
            } else {
                Ok(!self.get_code_at(L1_BLOCK_CONTRACT).await?.is_empty())
            }
        }
    }

    /// Fetches [`L1BlockFees`] from the [`L1_BLOCK_CONTRACT`].
    fn fetch_l1_fees(&self) -> impl Future<Output = TransportResult<L1BlockFees>> + Send
    where
        Self: Sized,
    {
        async move {
            let l1_block_contract = L1Block::new(L1_BLOCK_CONTRACT, self);
            let (base_fee, base_fee_scalar, blob_base_fee, blob_base_fee_scalar) = self
                .multicall()
                .add(l1_block_contract.basefee())
                .add(l1_block_contract.baseFeeScalar())
                .add(l1_block_contract.blobBaseFee())
                .add(l1_block_contract.blobBaseFeeScalar())
                .aggregate()
                .await
                .map_err(TransportErrorKind::custom)?;

            Ok(L1BlockFees {
                base_fee,
                base_fee_scalar: U256::from(base_fee_scalar),
                blob_base_fee,
                blob_base_fee_scalar: U256::from(blob_base_fee_scalar),
            })
        }
    }
}

impl<T> ProviderExt for T where T: Provider {}
