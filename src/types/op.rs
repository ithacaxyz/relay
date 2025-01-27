use alloy::{
    primitives::{Keccak256, B256},
    sol,
};
use serde::{Deserialize, Serialize};

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
