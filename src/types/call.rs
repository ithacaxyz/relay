//! ERC-7579 call type.

use alloy::{
    primitives::{b256, keccak256, Keccak256, B256},
    sol,
    sol_types::{Error, SolValue},
};
use std::vec::Vec;

/// EIP-712 typehash for ERC-7579 calls.
///
/// ```solidity
/// bytes32 public constant CALL_TYPEHASH = keccak256("Call(address target,uint256 value,bytes data)");
/// ```
const CALL_TYPEHASH: B256 =
    b256!("84fa2cf05cd88e992eae77e851af68a4ee278dcff6ef504e487a55b3baadfbe5");

sol! {
    /// ERC-7579 call struct.
    #[derive(Debug)]
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
        <Vec<Self>>::abi_decode(data, validate)
    }
}

/// A helper type representing a list of [`Call`] objects.
#[derive(Debug)]
pub struct CallArray(pub Vec<Call>);

impl CallArray {
    /// Decodes ABI‑encoded data into a `CallArray`.
    pub fn abi_decode(data: &[u8]) -> Result<Self, Error> {
        Ok(Self(Call::decode_array(data, false)?))
    }

    /// Computes a eip712 digest for the [`CallArray`].
    pub fn eip712_digest(&self) -> B256 {
        let mut hasher = Keccak256::new();

        for call in &self.0 {
            let mut call_hasher = Keccak256::new();

            call_hasher.update(CALL_TYPEHASH);
            call_hasher.update(B256::left_padding_from(call.target.as_ref()));
            call_hasher.update(call.value.to_be_bytes::<32>());
            call_hasher.update(keccak256(&call.data));

            hasher.update(call_hasher.finalize())
        }
        hasher.finalize()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::bytes;

    #[test]
    fn test_eip712() {
        let execution_data = bytes!(
            "00000000000000000000000000000000"
            "00000000000000000000000000000020"
            "00000000000000000000000000000000"
            "00000000000000000000000000000001"
            "00000000000000000000000000000000"
            "00000000000000000000000000000020"
            "0000000000000000000000007fa9385b"
            "e102ac3eac297483dd6233d62b3e1496"
            "00000000000000000000000000000000"
            "000000000000000000000000628c3be0"
            "00000000000000000000000000000000"
            "00000000000000000000000000000060"
            "00000000000000000000000000000000"
            "00000000000000000000000000000144"
            "3c78f395000000000000000000000000"
            "00000000000000000000000000000000"
            "00000020000000000000000000000000"
            "00000000000000000000000000000000"
            "000000e32c67f61a578060c3776c5384"
            "f017e2f74184e2aeb81b3679c6d44b6d"
            "b88522eeffffffff0000000000000000"
            "00000000000000000000000000000000"
            "000000000000002c3d3d3d3d363d3d37"
            "363d73f62849f9a0b5bf2913b396098f"
            "7c7019b51a820a5af43d3d93803e602a"
            "57fd5bf3000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
            "00000000000000000000000000000000"
        );

        assert_eq!(
            CallArray::abi_decode(&execution_data).unwrap().eip712_digest(),
            b256!("fb7a1aa00a28505936467cbfa2f4f747b20fa93e99d55e9450135c0f9e624b2d")
        )
    }
}
