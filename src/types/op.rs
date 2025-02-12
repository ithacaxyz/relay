use super::Call;
use alloy::{
    dyn_abi::Eip712Domain,
    primitives::{Address, ChainId, Keccak256, B256, U256},
    sol,
    sol_types::{SolStruct, SolValue},
};
use serde::{Deserialize, Serialize};

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
}

mod eip712 {
    use crate::types::Call;
    use alloy::sol;

    sol! {
        struct UserOp {
            bool multichain;
            address eoa;
            Call[] calls;
            uint256 nonce;
            uint256 nonceSalt;
            address payer;
            address paymentToken;
            uint256 paymentMaxAmount;
            uint256 paymentPerGas;
            uint256 combinedGas;
        }
    }
}

impl UserOp {
    /// Calculate the EIP-712 digest of the [`UserOp`], which is the digest signed for the
    /// `signature` field of the [`UserOp`].
    pub fn eip712_digest(
        &self,
        domain_verifying_contract: Address,
        chain_id: ChainId,
        nonce_salt: U256,
    ) -> Result<B256, alloy::sol_types::Error> {
        let is_odd_nonce = self.nonce.bit(0);

        Ok(eip712::UserOp {
            multichain: is_odd_nonce,
            eoa: self.eoa,
            calls: <Vec<Call>>::abi_decode(&self.executionData, false)?,
            nonce: self.nonce,
            nonceSalt: nonce_salt,
            payer: self.payer,
            paymentToken: self.paymentToken,
            paymentMaxAmount: self.paymentMaxAmount,
            paymentPerGas: self.paymentPerGas,
            combinedGas: self.combinedGas,
        }
        .eip712_signing_hash(&Eip712Domain::new(
            Some("EntryPoint".into()),
            Some("0.0.1".into()),
            (!is_odd_nonce).then(|| U256::from(chain_id)),
            Some(domain_verifying_contract),
            None,
        )))
    }

    /// Calculate a digest of the [`UserOp`], used for checksumming.
    ///
    /// # Note
    ///
    /// Only some fields are hashed.
    pub fn digest(&self) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update(self.eoa);
        hasher.update(&self.executionData);
        hasher.update(self.nonce.to_be_bytes::<32>());
        hasher.update(self.paymentToken);
        hasher.finalize()
    }
}

#[cfg(test)]
mod tests {
    use crate::signer::LocalOrAws;
    use alloy::{
        primitives::{address, b256, bytes, Address},
        signers::Signer,
        sol_types::SolValue,
    };

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
                    U256::ZERO
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
                    U256::ZERO
                )
                .unwrap(),
            b256!("0xaada23e8e365c4e46e9f3ab907a46d149d13e4cfc0355a708093ad93b157448c")
        );
    }

    #[tokio::test]
    async fn user_op_with_signature() {
        let mut user_op = UserOp {
            eoa: address!("E017A867c7204Fd596aE3141a5B194596849A196"),
            executionData: bytes!(
                "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000007fa9385be102ac3eac297483dd6233d62b3e1496000000000000000000000000000000000000000000000000000000009009e8ec000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000443c78f3950000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            ),
            nonce: U256::from(1),
            payer: Address::ZERO,
            paymentToken: address!("c7183455a4c133ae270771860664b6b7ec320bb1"),
            paymentRecipient: Address::ZERO,
            paymentAmount: U256::from(1021265804),
            paymentMaxAmount: U256::from(1021265804),
            paymentPerGas: U256::ZERO,
            combinedGas: U256::from(10000000u64),
            signature: bytes!(""),
        };

        let expected_digest =
            b256!("0x989f224e1d07735dd8c96c72f9dcb702fbe7a4d9133f331c6e066aee415a1678");
        assert_eq!(
            user_op
                .eip712_digest(
                    address!("307AF7d28AfEE82092aA95D35644898311CA5360"),
                    31337,
                    U256::from(23)
                )
                .unwrap(),
            expected_digest
        );

        let signer = LocalOrAws::load(
            "0x44a8f44ef7307087c960f8bfcbd95f7a1c9a2f505d438d1750dc947cfedb4b4a",
            None,
        )
        .await
        .unwrap();
        user_op.signature = signer.sign_hash(&expected_digest).await.unwrap().as_bytes().into();

        assert_eq!(
            user_op.signature,
            bytes!("0x80ee9c354e39d09a28ba9af6258843ea125e39f9af26c8372898998975a7d9594599380e39cd753414c4aa18987a1e6de52858e8a16b59cd3fb5ca52deb85f341c")
        );

        assert_eq!(
            user_op.abi_encode(),
            bytes!("0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000e017a867c7204fd596ae3141a5b194596849a196000000000000000000000000000000000000000000000000000000000000016000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c7183455a4c133ae270771860664b6b7ec320bb10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003cdf478c000000000000000000000000000000000000000000000000000000003cdf478c0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000098968000000000000000000000000000000000000000000000000000000000000002c000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000007fa9385be102ac3eac297483dd6233d62b3e1496000000000000000000000000000000000000000000000000000000009009e8ec000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000443c78f3950000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004180ee9c354e39d09a28ba9af6258843ea125e39f9af26c8372898998975a7d9594599380e39cd753414c4aa18987a1e6de52858e8a16b59cd3fb5ca52deb85f341c00000000000000000000000000000000000000000000000000000000000000"));
    }
}
