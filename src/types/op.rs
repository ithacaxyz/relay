use super::CallArray;
use alloy::{
    dyn_abi::Eip712Domain,
    primitives::{b256, keccak256, Address, ChainId, Keccak256, B256, U256},
    sol,
};
use serde::{Deserialize, Serialize};

/// For EIP712 signature digest calculation for the `execute` function.
///
/// ```solidity
/// bytes32 public constant USER_OP_TYPEHASH = keccak256("UserOp(bool multichain,address eoa,Call[] calls,uint256 nonce,uint256 nonceSalt,address payer,address paymentToken,uint256 paymentMaxAmount,uint256 paymentPerGas,uint256 combinedGas)Call(address target,uint256 value,bytes data)");
/// ```
const USER_OP_TYPEHASH: B256 =
    b256!("0xc3607e2f6b50396b4728b4863949155412094a746596309e725db1d2d315053b");

/// For EIP712 signature digest of an odd nonce.
const ODD_NONCE: B256 = b256!("0000000000000000000000000000000000000000000000000000000000000001");

sol! {
    /// A struct to hold the user operation fields.
    ///
    /// Since L2s already include calldata compression with savings forwarded to users,
    /// we don't need to be too concerned about calldata overhead.
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct UserOp {
        /// The user's address.
        address eoa;
        /// An encoded array of calls, using ERC7579 batch execution encoding.
        /// `abi.encode(calls)`, where `calls` is an array of type `Call[]`.
        /// This allows for more efficient safe forwarding to the EOA.
        bytes executionData;
        /// Per delegated EOA.
        uint256 nonce;
        /// The account paying the payment token.
        /// If this is `address(0)`, it defaults to the `eoa`.
        address payer;
        /// The ERC20 or native token used to pay for gas.
        address paymentToken;
        /// The payment recipient for the ERC20 token.
        /// Excluded from signature. The filler can replace this with their own address.
        /// This enables multiple fillers, allowing for competitive filling, better uptime.
        /// If `address(0)`, the payment will be accrued by the entry point.
        address paymentRecipient;
        /// The amount of the token to pay.
        /// Excluded from signature. This will be required to be less than `paymentMaxAmount`.
        uint256 paymentAmount;
        /// The maximum amount of the token to pay.
        uint256 paymentMaxAmount;
        /// The amount of ERC20 to pay per gas spent. For calculation of refunds.
        /// If this is left at zero, it will be treated as infinity (i.e. no refunds).
        uint256 paymentPerGas;
        /// The combined gas limit for payment, verification, and calling the EOA.
        uint256 combinedGas;
        /// The wrapped signature.
        /// `abi.encodePacked(innerSignature, keyHash, prehash)`.
        bytes signature;
    }

    /// A partial [`UserOp`] used for fee estimation.
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct PartialUserOp {
        /// The user's address.
        address eoa;
        /// An encoded array of calls, using ERC7579 batch execution encoding.
        /// `abi.encode(calls)`, where `calls` is an array of type `Call[]`.
        /// This allows for more efficient safe forwarding to the EOA.
        bytes executionData;
        /// Per delegated EOA.
        uint256 nonce;
    }

    /// The signature of a [`UserOp`].
    struct Signature {
        bytes innerSignature;
        bytes32 keyHash;
        bool prehash;
    }

    /// Returns the nonce salt.
    function nonceSalt() public view virtual returns (uint256);
}

impl UserOp {
    pub fn eip712_digest(
        &self,
        domain_verifying_contract: Address,
        chain_id: ChainId,
        nonce_salt: B256,
    ) -> Result<B256, alloy::sol_types::Error> {
        let is_odd_nonce = self.nonce.bit(0);

        let mut hasher = Keccak256::new();
        hasher.update(USER_OP_TYPEHASH);
        hasher.update(is_odd_nonce.then_some(ODD_NONCE).unwrap_or_default());
        hasher.update(B256::left_padding_from(self.eoa.as_ref()));
        hasher.update(CallArray::abi_decode(&self.executionData)?.eip712_digest());
        hasher.update(self.nonce.to_be_bytes::<32>());
        hasher.update(nonce_salt);
        hasher.update(B256::left_padding_from(self.payer.as_ref()));
        hasher.update(B256::left_padding_from(self.paymentToken.as_ref()));
        hasher.update(self.paymentMaxAmount.to_be_bytes::<32>());
        hasher.update(self.paymentPerGas.to_be_bytes::<32>());
        hasher.update(self.combinedGas.to_be_bytes::<32>());
        let op = hasher.finalize();

        let domain = Eip712Domain::new(
            Some("EntryPoint".into()),
            Some("0.0.1".into()),
            (!is_odd_nonce).then(|| U256::from(chain_id)),
            Some(domain_verifying_contract),
            None,
        );

        Ok(keccak256([&[0x19, 0x01], &domain.hash_struct()[..], &op[..]].concat()))
    }

    pub fn digest(&self) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update(self.eoa);
        hasher.update(&self.executionData);
        hasher.update(self.nonce.to_be_bytes::<32>());
        hasher.finalize()
    }
}

impl PartialUserOp {
    pub fn digest(&self) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update(self.eoa);
        hasher.update(&self.executionData);
        hasher.update(self.nonce.to_be_bytes::<32>());
        hasher.finalize()
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{address, bytes, Address};

    use super::*;

    #[test]
    fn user_op_eip712_digest() {
        let mut user_op = UserOp {
            eoa: address!("7b9fc63d6d9e8f94e90d1b0abfc3f611de2638d0"),
            executionData: bytes!(
                "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000007fa9385be102ac3eac297483dd6233d62b3e149600000000000000000000000000000000000000000000000000000000628c3be0000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001443c78f395000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000e32c67f61a578060c3776c5384f017e2f74184e2aeb81b3679c6d44b6db88522eeffffffff000000000000000000000000000000000000000000000000000000000000002c3d3d3d3d363d3d37363d73f62849f9a0b5bf2913b396098f7c7019b51a820a5af43d3d93803e602a57fd5bf300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            ),
            nonce: U256::from(31338),
            payer: Address::ZERO,
            paymentToken: address!("c7183455a4c133ae270771860664b6b7ec320bb1"),
            paymentRecipient: Address::ZERO,
            paymentAmount: U256::from(3822601006u64),
            paymentMaxAmount: U256::from(3822601006u64),
            paymentPerGas: U256::ZERO,
            combinedGas: U256::from(10_000_000u64),
            signature: bytes!(""),
        };

        // Even nonce (with chain id)
        user_op.nonce = U256::from(31338);
        assert_eq!(
            user_op
                .eip712_digest(
                    address!("307AF7d28AfEE82092aA95D35644898311CA5360"),
                    31337,
                    B256::ZERO
                )
                .unwrap(),
            b256!("0x61b486d7713e2524feea197c603d8f8a59192bb7fc3c3c232536d8e18b35fde6")
        );

        // Odd nonce (no chain id)
        user_op.nonce = U256::from(31337);
        assert_eq!(
            user_op
                .eip712_digest(
                    address!("307AF7d28AfEE82092aA95D35644898311CA5360"),
                    31337,
                    B256::ZERO
                )
                .unwrap(),
            b256!("0xaada23e8e365c4e46e9f3ab907a46d149d13e4cfc0355a708093ad93b157448c")
        );
    }
}
