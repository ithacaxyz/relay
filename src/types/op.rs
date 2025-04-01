use super::{Call, IDelegation::authorizeCall, Key, PREPInitData};
use alloy::{
    primitives::{Address, B256, Bytes, Keccak256, U256, keccak256},
    sol,
    sol_types::{SolCall, SolValue},
    uint,
};
use serde::{Deserialize, Serialize};

/// Nonce prefix to signal that the payload is to be signed with EIP-712 without the chain ID.
pub const MULTICHAIN_NONCE_PREFIX: U256 = uint!(0xc1d0_U256);

sol! {
    /// A struct to hold the user operation fields.
    ///
    /// Since L2s already include calldata compression with savings forwarded to users,
    /// we don't need to be too concerned about calldata overhead.
    #[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct UserOp {
        /// The user's address.
        address eoa;
        /// An encoded array of calls, using ERC7579 batch execution encoding.
        ///
        /// The format is `abi.encode(calls)`, where `calls` is an array of type `Call[]`.
        ///
        /// This allows for more efficient safe forwarding to the EOA.
        bytes executionData;
        /// Per delegated EOA.
        ///
        /// # Memory layout
        ///
        /// Each nonce has the following memory layout:
        ///
        ///      ,----------------------------------------------------.
        /// bits | 0-191 (192 bits)                | 192-255 (64 bits)|
        ///      |---------------------------------|------------------|
        /// desc | sequence key                    | sequential nonce |
        ///      `----------------.----------------|------------------'
        ///                       |
        ///                       v
        ///      ,-------------------------------------.
        /// bits | 0-15 (16 bits)  | 16-191 (176 bits) |
        ///      |-------------------------------------|
        /// desc | multichain flag | remainder         |
        ///      `-------------------------------------'
        ///
        /// If the upper 16 bits of the sequence key is `0xc1d0`, then the EIP-712 has
        /// of the UserOp will exlude the chain ID.
        ///
        /// # Ordering
        ///
        /// Ordering matters within a sequence key, but not between sequence keys.
        ///
        /// This means that users who do not care about the order of specific userops
        /// can sign their userops using a random sequence key. On the other hand, if
        /// they do care about ordering, they would use the same sequence key.
        uint256 nonce;
        /// The account paying the payment token.
        ///
        /// If this is `address(0)`, it defaults to the `eoa`.
        address payer;
        /// The ERC20 or native token used to pay for gas.
        address paymentToken;
        /// The payment recipient for the ERC20 token.
        ///
        /// Excluded from signature. The filler can replace this with their own address.
        ///
        /// This enables multiple fillers, allowing for competitive filling, better uptime.
        /// If `address(0)`, the payment will be accrued by the entry point.
        address paymentRecipient;
        /// The amount of the token to pay.
        ///
        /// Excluded from signature.
        ///
        /// This will be required to be less than `paymentMaxAmount`.
        uint256 paymentAmount;
        /// The maximum amount of the token to pay.
        uint256 paymentMaxAmount;
        /// The amount of ERC20 to pay per gas spent. For calculation of refunds.
        ///
        /// If this is left at zero, it will be treated as infinity (i.e. no refunds).
        uint256 paymentPerGas;
        /// The combined gas limit for payment, verification, and calling the EOA.
        uint256 combinedGas;
        /// The wrapped signature.
        ///
        /// The format is `abi.encodePacked(innerSignature, keyHash, prehash)` for most signatures,
        /// except if it is signed by the EOA root key, in which case `abi.encodePacked(r, s, v)` is valid as well.
        bytes signature;
        /// Optional data for `initPREP` on the delegation.
        ///
        /// Excluded from signature.
        bytes initData;
        /// Optional array of encoded UserOps that will be verified and executed
        /// after PREP (if any) and before the validation of the overall UserOp.
        bytes[] encodedPreOps;
        /// Optional payment signature to be passed into the `compensate` function
        /// on the `payer`. This signature is NOT included in the EIP712 signature.
        bytes paymentSignature;
    }
}

/// A partial [`UserOp`] used for fee estimation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartialUserOp {
    /// The user's address.
    pub eoa: Address,
    /// An encoded array of calls, using ERC7579 batch execution encoding.
    ///
    /// The format is `abi.encode(calls)`, where `calls` is an array of type `Call[]`.
    ///
    /// This allows for more efficient safe forwarding to the EOA.
    pub execution_data: Bytes,
    /// Per delegated EOA.
    pub nonce: Option<U256>,
    /// Optional data for `initPREP` on the delegation.
    ///
    /// Excluded from signature.
    pub init_data: Option<Bytes>,
    /// Optional array of encoded UserOps that will be verified and executed before the
    /// verification of the overall UserOp.
    pub pre_ops: Vec<UserOp>,
}

mod eip712 {
    use crate::types::Call;
    use alloy::sol;

    sol! {
        #[derive(serde::Serialize)]
        struct UserOp {
            bool multichain;
            address eoa;
            Call[] calls;
            uint256 nonce;
            address payer;
            address paymentToken;
            uint256 paymentMaxAmount;
            uint256 paymentPerGas;
            uint256 combinedGas;
            bytes[] encodedPreOps;
        }
    }
}

impl UserOp {
    /// Whether this [`UserOp`] is multichain.
    ///
    /// If the op is multichain, the EIP712 domain used for the signing hash of the op should not
    /// include a chain ID.
    pub fn is_multichain(&self) -> bool {
        self.nonce >> 240 == MULTICHAIN_NONCE_PREFIX
    }

    /// Get the EIP712 encoding of the [`UserOp`].
    pub fn as_eip712(&self) -> Result<eip712::UserOp, alloy::sol_types::Error> {
        let multichain = self.is_multichain();

        Ok(eip712::UserOp {
            multichain,
            eoa: self.eoa,
            calls: <Vec<Call>>::abi_decode(&self.executionData, false)?,
            nonce: self.nonce,
            payer: self.payer,
            paymentToken: self.paymentToken,
            paymentMaxAmount: self.paymentMaxAmount,
            paymentPerGas: self.paymentPerGas,
            combinedGas: self.combinedGas,
            encodedPreOps: self.encodedPreOps.clone(),
        })
    }

    /// Calculate a digest of the [`UserOp`], used for checksumming.
    ///
    /// # Note
    ///
    /// Only some fields are hashed.
    pub fn digest(&self) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update([self.is_multichain() as u8]);
        hasher.update(self.eoa);
        hasher.update(&self.executionData);
        hasher.update(self.nonce.to_be_bytes::<32>());
        hasher.update(self.payer);
        hasher.update(self.paymentToken);
        hasher.update(self.paymentMaxAmount.to_be_bytes::<32>());
        hasher.update(self.paymentPerGas.to_be_bytes::<32>());
        hasher.update(self.combinedGas.to_be_bytes::<32>());
        let pre_ops_hash = {
            let mut hasher = Keccak256::new();
            for pre_op in self.encodedPreOps.iter() {
                hasher.update(keccak256(pre_op));
            }
            hasher.finalize()
        };
        hasher.update(pre_ops_hash);
        hasher.finalize()
    }

    /// Returns all keys authorized in `pre_ops`.
    pub fn pre_authorized_keys(&self) -> Result<Vec<Key>, alloy::sol_types::Error> {
        let mut all_keys = Vec::with_capacity(self.encodedPreOps.len());
        for encoded_op in &self.encodedPreOps {
            let op = UserOp::abi_decode(encoded_op, false)?;
            all_keys.extend(op.authorized_keys().into_iter().flatten());
        }
        Ok(all_keys)
    }

    /// Returns all keys authorized in the current [`UserOp`] including `pre_ops`, `executionData`
    /// and `initData`.
    pub fn authorized_keys(&self) -> Result<Vec<Key>, alloy::sol_types::Error> {
        // Decode keys from the execution data.
        let keys =
            Vec::<Call>::abi_decode(&self.executionData, false)?.into_iter().filter_map(|call| {
                // Attempt to decode the call as an authorizeCall; ignore if unsuccessful.
                authorizeCall::abi_decode(&call.data, false).ok().map(|decoded| decoded.key)
            });

        // Decode keys from initData, if it exists.
        let mut keys: Vec<Key> = if !self.initData.is_empty() {
            let prep = PREPInitData::abi_decode_params(&self.initData, false)?;

            keys.chain(prep.calls.into_iter().filter_map(|call| {
                // Attempt to decode the call as an authorizeCall; ignore if unsuccessful.
                authorizeCall::abi_decode(&call.data, false).ok().map(|decoded| decoded.key)
            }))
            .collect()
        } else {
            keys.collect()
        };

        // Extend with pre-authorized keys.
        keys.extend(self.pre_authorized_keys()?);

        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signers::DynSigner;
    use alloy::{
        dyn_abi::Eip712Domain,
        primitives::{Address, Bytes, address, b256, bytes},
        sol_types::{SolStruct, SolValue},
    };

    #[test]
    fn is_multichain() {
        assert!(!UserOp::default().is_multichain());
        assert!(
            UserOp { nonce: U256::from(MULTICHAIN_NONCE_PREFIX << 240), ..Default::default() }
                .is_multichain()
        );
        assert!(
            UserOp {
                nonce: (MULTICHAIN_NONCE_PREFIX << 240) | U256::from(31338),
                ..Default::default()
            }
            .is_multichain()
        )
    }

    #[test]
    fn user_op_eip712_digest() {
        let mut user_op = UserOp {
            eoa: address!("0x7b9fc63d6d9e8f94e90d1b0abfc3f611de2638d0"),
            executionData: bytes!(
                "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000007fa9385be102ac3eac297483dd6233d62b3e149600000000000000000000000000000000000000000000000000000000628c3be0000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001443c78f395000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000e32c67f61a578060c3776c5384f017e2f74184e2aeb81b3679c6d44b6db88522eeffffffff000000000000000000000000000000000000000000000000000000000000002c3d3d3d3d363d3d37363d73f62849f9a0b5bf2913b396098f7c7019b51a820a5af43d3d93803e602a57fd5bf300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            ),
            nonce: U256::from(31338),
            payer: Address::ZERO,
            paymentToken: address!("0xc7183455a4c133ae270771860664b6b7ec320bb1"),
            paymentRecipient: Address::ZERO,
            paymentAmount: U256::from(3822601006u64),
            paymentMaxAmount: U256::from(3822601006u64),
            paymentPerGas: U256::ZERO,
            combinedGas: U256::from(10_000_000u64),
            signature: bytes!(""),
            initData: bytes!(""),
            encodedPreOps: vec![],
            paymentSignature: bytes!(""),
        };

        // Single chain op
        user_op.nonce = U256::from(31338);
        assert_eq!(
            user_op.as_eip712().unwrap().eip712_signing_hash(&Eip712Domain::new(
                Some("EntryPoint".into()),
                Some("0.0.1".into()),
                Some(U256::from(31337)),
                Some(address!("0x307AF7d28AfEE82092aA95D35644898311CA5360")),
                None
            )),
            b256!("0xa151c1bc143d2f0ead71e2f41355a3d945677a92085ab1597a5b53685c63a73e")
        );

        // Multichain op
        user_op.nonce = (MULTICHAIN_NONCE_PREFIX << 240) | U256::from(31338);
        assert_eq!(
            user_op.as_eip712().unwrap().eip712_signing_hash(&Eip712Domain::new(
                Some("EntryPoint".into()),
                Some("0.0.1".into()),
                None,
                Some(address!("0x307AF7d28AfEE82092aA95D35644898311CA5360")),
                None
            )),
            b256!("0xcb826e8a1d22dcc0318a262bfe4c09cbe8b0641478699b58b0fe5c1a909b6093")
        );
    }

    #[tokio::test]
    async fn user_op_with_signature() {
        let mut user_op = UserOp {
            eoa: address!("0xE017A867c7204Fd596aE3141a5B194596849A196"),
            executionData: bytes!(
                "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000007fa9385be102ac3eac297483dd6233d62b3e1496000000000000000000000000000000000000000000000000000000009009e8ec000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000443c78f3950000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            ),
            nonce: U256::from(1),
            payer: Address::ZERO,
            paymentToken: address!("0xc7183455a4c133ae270771860664b6b7ec320bb1"),
            paymentRecipient: Address::ZERO,
            paymentAmount: U256::from(1021265804),
            paymentMaxAmount: U256::from(1021265804),
            paymentPerGas: U256::ZERO,
            combinedGas: U256::from(10000000u64),
            signature: bytes!(""),
            initData: bytes!(""),
            encodedPreOps: vec![],
            paymentSignature: bytes!(""),
        };

        let expected_digest =
            b256!("0x92a8e751180c87f9aff0ec759f2caab9e91e6485584f8605b6379217d3a41846");
        assert_eq!(
            user_op.as_eip712().unwrap().eip712_signing_hash(&Eip712Domain::new(
                Some("EntryPoint".into()),
                Some("0.0.1".into()),
                None,
                Some(address!("0x307AF7d28AfEE82092aA95D35644898311CA5360")),
                None
            )),
            expected_digest
        );

        let signer = DynSigner::load(
            "0x44a8f44ef7307087c960f8bfcbd95f7a1c9a2f505d438d1750dc947cfedb4b4a",
            None,
        )
        .await
        .unwrap();
        user_op.signature = signer.sign_hash(&expected_digest).await.unwrap().as_bytes().into();

        assert_eq!(
            user_op.signature,
            bytes!(
                "0x0c1fd77b93e9bf66c4a106d26287942478393b1d5529d447b2def03665bf4e533a20fe5f0bcf8aa90b3102489a796f923f569e5d4828cbe7ecb13e2f2716026f1c"
            )
        );

        assert_eq!(
            Bytes::from(user_op.abi_encode()),
            bytes!(
                "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000e017a867c7204fd596ae3141a5b194596849a19600000000000000000000000000000000000000000000000000000000000001c000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c7183455a4c133ae270771860664b6b7ec320bb10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003cdf478c000000000000000000000000000000000000000000000000000000003cdf478c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000989680000000000000000000000000000000000000000000000000000000000000032000000000000000000000000000000000000000000000000000000000000003a000000000000000000000000000000000000000000000000000000000000003c000000000000000000000000000000000000000000000000000000000000003e000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000007fa9385be102ac3eac297483dd6233d62b3e1496000000000000000000000000000000000000000000000000000000009009e8ec000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000443c78f395000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000410c1fd77b93e9bf66c4a106d26287942478393b1d5529d447b2def03665bf4e533a20fe5f0bcf8aa90b3102489a796f923f569e5d4828cbe7ecb13e2f2716026f1c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
    }
}
