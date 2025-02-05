//! Call type used on ERC-7579.

use alloy::{
    primitives::{b256, Keccak256, B256},
    sol,
    sol_types::{Error, SolValue},
};
use std::vec::Vec;

/// For EIP712 signature digest calculation for the `execute` function.
///
/// ```solidity
/// bytes32 public constant CALL_TYPEHASH = keccak256("Call(address target,uint256 value,bytes data)");
/// ```
const CALL_TYPEHASH: B256 =
    b256!("84fa2cf05cd88e992eae77e851af68a4ee278dcff6ef504e487a55b3baadfbe5");

sol! {
    /// ERC-7579 call struct.
    struct Call {
        /// The call target.
        address target;
        /// Amount of native value to send to the target.
        uint256 value;
        /// The calldata bytes.
        bytes data;
    }

}

impl Call {
    /// Helper method to decode an array of `Call[]` into `Vec<Call>`.
    pub fn decode_array(data: &[u8], validate: bool) -> Result<Vec<Self>, Error> {
        <Vec<Call>>::abi_decode(data, validate)
    }
}

/// An helper type representing a list of [`Call`] objects.
pub struct CallArray(pub Vec<Call>);

impl CallArray {
    /// Decodes ABI‑encoded data into a `CallArray`.
    pub fn abi_decode(data: &[u8]) -> Result<Self, Error> {
        Ok(Self(Call::decode_array(data, false)?))
    }

    /// Computes a eip712 digest for the [`CallArray`].
    pub fn eip712_digest(&self) -> B256 {
        let mut hasher = Keccak256::new();
        let mut buf = [0u8; 32];

        for call in &self.0 {
            let mut call_hasher = Keccak256::new();

            hasher.update(CALL_TYPEHASH);

            // bytes32(uint256(uint160(target))
            buf[..20].copy_from_slice(call.target.as_ref());
            call_hasher.update(&buf);

            call_hasher.update(&call.value.to_be_bytes::<32>());
            call_hasher.update(&call.data);
        }
        hasher.finalize()
    }
}
