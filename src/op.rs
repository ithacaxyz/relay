//! Helpers for OP fee estimation.

use L1Block::L1BlockInstance;
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

impl<P: Provider> L1BlockInstance<P> {
    /// Fetches [`L1BlockFees`] via multicall.
    pub async fn fetch_fees(&self) -> TransportResult<L1BlockFees> {
        let (base_fee, base_fee_scalar, blob_base_fee, blob_base_fee_scalar) = self
            .provider()
            .multicall()
            .add(self.basefee())
            .add(self.baseFeeScalar())
            .add(self.blobBaseFee())
            .add(self.blobBaseFeeScalar())
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
