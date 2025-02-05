use super::CallArray;
use alloy::{
    dyn_abi::Eip712Domain,
    primitives::{b256, keccak256, ChainId, Keccak256, B256, U256},
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
}

impl UserOp {
    pub fn eip712_digest(
        &self,
        chain_id: ChainId,
        nonce_salt: B256,
    ) -> Result<B256, alloy::sol_types::Error> {
        let is_odd_nonce = self.nonce.bit(0);

        // Calculate OP digest
        let mut hasher = Keccak256::new();
        hasher.update(USER_OP_TYPEHASH);
        hasher.update(is_odd_nonce.then_some(ODD_NONCE).unwrap_or_default());
        hasher.update(self.eoa);
        hasher.update(CallArray::abi_decode(&self.executionData)?.eip712_digest());
        hasher.update(self.nonce.to_be_bytes::<32>());
        hasher.update(nonce_salt);
        hasher.update(self.payer);
        hasher.update(self.paymentToken);
        hasher.update(self.paymentMaxAmount.to_be_bytes::<32>());
        hasher.update(self.paymentPerGas.to_be_bytes::<32>());
        hasher.update(self.combinedGas.to_be_bytes::<32>());
        let op = hasher.finalize();

        let domain_separator = keccak256(
            &Eip712Domain::new(
                None,
                None,
                (!is_odd_nonce).then(|| U256::from(chain_id)),
                None,
                None,
            )
            .encode_data(),
        );

        Ok(keccak256([&[0x19, 0x01], &domain_separator[..], &op[..]].concat()))
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
