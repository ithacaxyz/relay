use super::{Call, IDelegation::authorizeCall, Key, OrchestratorContract, PREPInitData};
use crate::types::Orchestrator;
use alloy::{
    dyn_abi::TypedData,
    primitives::{Address, B256, Bytes, Keccak256, U256, aliases::U192, keccak256},
    providers::DynProvider,
    sol,
    sol_types::{SolCall, SolStruct, SolValue},
    uint,
};
use serde::{Deserialize, Serialize};

/// Nonce prefix to signal that the payload is to be signed with EIP-712 without the chain ID.
pub const MULTICHAIN_NONCE_PREFIX: U256 = uint!(0xc1d0_U256);

/// Nonce prefix to signal that the payload is to be signed with EIP-712 without the chain ID.
pub const MULTICHAIN_NONCE_PREFIX_U192: U192 = uint!(0xc1d0_U192);

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
        /// The amount of the token to pay, before the call batch is executed
        /// This will be required to be less than `totalPaymentMaxAmount`.
        uint256 prePaymentMaxAmount;
        /// The maximum amount of the token to pay.
        uint256 totalPaymentMaxAmount;
        /// The combined gas limit for payment, verification, and calling the EOA.
        uint256 combinedGas;
        /// Optional array of encoded UserOps that will be verified and executed
        /// after PREP (if any) and before the validation of the overall UserOp.
        /// A PreOp will NOT have its gas limit or payment applied.
        /// The overall UserOp's gas limit and payment will be applied, encompassing all its PreOps.
        /// The execution of a PreOp will check and increment the nonce in the PreOp.
        /// If at any point, any PreOp cannot be verified to be correct, or fails in execution,
        /// the overall UserOp will revert before validation, and execute will return a non-zero error.
        /// A PreOp can contain PreOps, forming a tree structure.
        /// The `executionData` tree will be executed in post-order (i.e. left -> right -> current).
        /// The `encodedPreOps` are included in the EIP712 signature, which enables execution order
        /// to be enforced on-the-fly even if the nonces are from different sequences.
        bytes[] encodedPreOps;
        ////////////////////////////////////////////////////////////////////////
        // Additional Fields (Not included in EIP-712)
        ////////////////////////////////////////////////////////////////////////
        /// Optional data for `initPREP` on the delegation.
        /// This is encoded using ERC7821 style batch execution encoding.
        /// (ERC7821 is a variant of ERC7579).
        /// `abi.encode(calls, abi.encodePacked(bytes32(saltAndDelegation)))`,
        /// where `calls` is of type `Call[]`,
        /// and `saltAndDelegation` is `bytes32((uint256(salt) << 160) | uint160(delegation))`.
        bytes initData;
        /// The actual pre payment amount, requested by the filler. MUST be less than or equal to `prePaymentMaxAmount`
        uint256 prePaymentAmount;
        /// The actual total payment amount, requested by the filler. MUST be less than or equal to `totalPaymentMaxAmount`
        uint256 totalPaymentAmount;
        /// The payment recipient for the ERC20 token.
        /// Excluded from signature. The filler can replace this with their own address.
        /// This enables multiple fillers, allowing for competitive filling, better uptime.
        address paymentRecipient;
        /// The wrapped signature.
        /// `abi.encodePacked(innerSignature, keyHash, prehash)`.
        bytes signature;
        /// Optional payment signature to be passed into the `compensate` function
        /// on the `payer`. This signature is NOT included in the EIP712 signature.
        bytes paymentSignature;
        /// Optional. If non-zero, the EOA must use `supportedDelegationImplementation`.
        /// Otherwise, if left as `address(0)`, any EOA implementation will be supported.
        /// This field is NOT included in the EIP712 signature.
        address supportedDelegationImplementation;
    }


    /// A struct to hold the fields for a PreOp.
    /// Like a UserOp with a subset of fields.
    #[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct PreOp {
        /// The user's address.
        ///
        /// This can be set to `address(0)`, which allows it to be
        /// coalesced to the parent UserOp's EOA.
        address eoa;
        /// An encoded array of calls, using ERC7579 batch execution encoding.
        ///
        /// `abi.encode(calls)`, where `calls` is of type `Call[]`.
        /// This allows for more efficient safe forwarding to the EOA.
        bytes executionData;
        /// Per delegated EOA. Same logic as the `nonce` in UserOp.
        uint256 nonce;
        /// The wrapped signature.
        ///
        /// `abi.encodePacked(innerSignature, keyHash, prehash)`.
        bytes signature;
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
    pub nonce: U256,
    /// Optional data for `initPREP` on the delegation.
    ///
    /// Excluded from signature.
    pub init_data: Option<Bytes>,
    /// Optional payer of the gas.
    pub payer: Option<Address>,
    /// Optional array of encoded PreOps that will be verified and executed before the
    /// verification of the overall UserOp.
    pub pre_ops: Vec<PreOp>,
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
            uint256 prePaymentMaxAmount;
            uint256 totalPaymentMaxAmount;
            uint256 combinedGas;
            bytes[] encodedPreOps;
        }

        #[derive(serde::Serialize)]
        struct PreOp {
            bool multichain;
            address eoa;
            Call[] calls;
            uint256 nonce;
        }
    }
}

impl UserOp {
    /// Sets the payment amount fields so it has the same behaviour as legacy UserOp.
    pub fn set_legacy_payment_amount(&mut self, amount: U256) {
        self.prePaymentAmount = amount;
        self.prePaymentMaxAmount = amount;
        self.totalPaymentAmount = amount;
        self.totalPaymentMaxAmount = amount;
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
        hasher.update(self.prePaymentMaxAmount.to_be_bytes::<32>());
        hasher.update(self.totalPaymentMaxAmount.to_be_bytes::<32>());
        hasher.update(self.combinedGas.to_be_bytes::<32>());
        let pre_ops_hash = {
            let mut hasher = Keccak256::new();
            for pre_op in self.encodedPreOps.iter() {
                hasher.update(keccak256(pre_op));
            }
            hasher.finalize()
        };
        hasher.update(pre_ops_hash);
        hasher.update(self.supportedDelegationImplementation);
        hasher.finalize()
    }

    /// Returns all keys authorized in `pre_ops`.
    pub fn pre_authorized_keys(&self) -> Result<Vec<Key>, alloy::sol_types::Error> {
        let mut all_keys = Vec::with_capacity(self.encodedPreOps.len());
        for encoded_op in &self.encodedPreOps {
            let pre_op = PreOp::abi_decode(encoded_op)?;
            all_keys.extend(pre_op.authorized_keys_from_execution_data()?);
        }
        Ok(all_keys)
    }

    /// Encodes this userop into calldata for [`OrchestratorContract::executeCall`].
    pub fn encode_execute(&self) -> Bytes {
        OrchestratorContract::executeCall { encodedUserOp: self.abi_encode().into() }
            .abi_encode()
            .into()
    }
}

/// Shared behaviour between [`UserOp`] and [`PreOp`].
pub trait Op {
    /// Returns `executionData`.
    fn execution_data(&self) -> &[u8];

    /// Returns `nonce`.
    fn nonce(&self) -> U256;

    /// Returns the decoded calls from `executionData`.
    fn calls(&self) -> Result<Vec<Call>, alloy::sol_types::Error> {
        <Vec<Call>>::abi_decode(self.execution_data())
    }

    /// Returns all keys authorized in `executionData`.
    fn authorized_keys_from_execution_data(
        &self,
    ) -> Result<impl Iterator<Item = Key>, alloy::sol_types::Error> {
        // Decode keys from the execution data.
        Ok(self.calls()?.into_iter().filter_map(|call| {
            // Attempt to decode the call as an authorizeCall; ignore if unsuccessful.
            authorizeCall::abi_decode(&call.data).ok().map(|decoded| decoded.key)
        }))
    }

    /// Returns all keys authorized in the current op.
    fn authorized_keys(&self) -> Result<Vec<Key>, alloy::sol_types::Error> {
        Ok(self.authorized_keys_from_execution_data()?.collect())
    }

    /// Whether this op is multichain.
    ///
    /// If the op is multichain, the EIP712 domain used for the signing hash of the op should not
    /// include a chain ID.
    fn is_multichain(&self) -> bool {
        self.nonce() >> 240 == MULTICHAIN_NONCE_PREFIX
    }

    /// Get the EIP712 encoding of the op.
    fn as_eip712(&self) -> Result<impl SolStruct + Serialize + Send, alloy::sol_types::Error>;

    /// Computes the EIP-712 digest that the user must sign.
    fn compute_eip712_data(
        &self,
        orchestrator_address: Address,
        provider: &DynProvider,
    ) -> impl Future<Output = eyre::Result<(B256, TypedData)>> + Send
    where
        Self: Sync,
    {
        async move {
            // Create the orchestrator instance with the same overrides.
            let orchestrator = Orchestrator::new(orchestrator_address, provider);

            // Prepare the EIP-712 payload and domain
            let payload = self.as_eip712()?;
            let domain = orchestrator.eip712_domain(self.is_multichain()).await?;

            // Return the computed signing hash (digest).
            let digest = payload.eip712_signing_hash(&domain);
            let typed_data = TypedData::from_struct(&payload, Some(domain));

            debug_assert_eq!(Ok(digest), typed_data.eip712_signing_hash());

            Ok((digest, typed_data))
        }
    }
}

impl Op for PreOp {
    fn execution_data(&self) -> &[u8] {
        &self.executionData
    }

    fn nonce(&self) -> U256 {
        self.nonce
    }

    fn as_eip712(&self) -> Result<impl SolStruct + Serialize + Send, alloy::sol_types::Error> {
        Ok(eip712::PreOp {
            multichain: self.is_multichain(),
            eoa: self.eoa,
            calls: self.calls()?,
            nonce: self.nonce,
        })
    }
}

impl Op for UserOp {
    fn as_eip712(&self) -> Result<impl SolStruct + Serialize + Send, alloy::sol_types::Error> {
        Ok(eip712::UserOp {
            multichain: self.is_multichain(),
            eoa: self.eoa,
            calls: self.calls()?,
            nonce: self.nonce,
            payer: self.payer,
            paymentToken: self.paymentToken,
            prePaymentMaxAmount: self.prePaymentMaxAmount,
            totalPaymentMaxAmount: self.totalPaymentMaxAmount,
            combinedGas: self.combinedGas,
            encodedPreOps: self.encodedPreOps.clone(),
        })
    }

    fn execution_data(&self) -> &[u8] {
        &self.executionData
    }

    fn nonce(&self) -> U256 {
        self.nonce
    }

    /// Returns all keys authorized in the current [`UserOp`] including `pre_ops`, `executionData`
    /// and `initData`.
    fn authorized_keys(&self) -> Result<Vec<Key>, alloy::sol_types::Error> {
        let keys = self.authorized_keys_from_execution_data()?;

        // Decode keys from initData, if it exists.
        let mut keys: Vec<Key> = if !self.initData.is_empty() {
            let prep = PREPInitData::abi_decode_params(&self.initData)?;

            keys.chain(prep.calls.into_iter().filter_map(|call| {
                // Attempt to decode the call as an authorizeCall; ignore if unsuccessful.
                authorizeCall::abi_decode(&call.data).ok().map(|decoded| decoded.key)
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
            prePaymentMaxAmount: U256::from(3822601006u64),
            totalPaymentMaxAmount: U256::from(3822601006u64),
            combinedGas: U256::from(10_000_000u64),
            initData: bytes!(""),
            encodedPreOps: vec![],
            prePaymentAmount: U256::from(3822601006u64),
            totalPaymentAmount: U256::from(3822601006u64),
            paymentRecipient: Address::ZERO,
            signature: bytes!(""),
            paymentSignature: bytes!(""),
            supportedDelegationImplementation: Address::ZERO,
        };

        // Single chain op
        user_op.nonce = U256::from(31338);
        assert_eq!(
            user_op.as_eip712().unwrap().eip712_signing_hash(&Eip712Domain::new(
                Some("Orchestrator".into()),
                Some("0.0.1".into()),
                Some(U256::from(31337)),
                Some(address!("0x307AF7d28AfEE82092aA95D35644898311CA5360")),
                None
            )),
            b256!("0xbd81056e33133c05750c5d203d7016828d1489750a5b4025c927f50f5eb73acf")
        );

        // Multichain op
        user_op.nonce = (MULTICHAIN_NONCE_PREFIX << 240) | U256::from(31338);
        assert_eq!(
            user_op.as_eip712().unwrap().eip712_signing_hash(&Eip712Domain::new(
                Some("Orchestrator".into()),
                Some("0.0.1".into()),
                None,
                Some(address!("0x307AF7d28AfEE82092aA95D35644898311CA5360")),
                None
            )),
            b256!("0xd572ea7b6dd17e36cf3ccbd40510428f1bab273a1b52bbb58639356a461577f8")
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
            prePaymentMaxAmount: U256::from(1021265804),
            totalPaymentMaxAmount: U256::from(1021265804),
            combinedGas: U256::from(10000000u64),
            initData: bytes!(""),
            encodedPreOps: vec![],
            prePaymentAmount: U256::from(1021265804),
            totalPaymentAmount: U256::from(1021265804),
            paymentRecipient: Address::ZERO,
            signature: bytes!(""),
            paymentSignature: bytes!(""),
            supportedDelegationImplementation: Address::ZERO,
        };

        let expected_digest =
            b256!("0x14e830a607161a7905565356517352a18f8c105f10b940a74bd65c11a22f25c0");
        assert_eq!(
            user_op.as_eip712().unwrap().eip712_signing_hash(&Eip712Domain::new(
                Some("Orchestrator".into()),
                Some("0.0.1".into()),
                None,
                Some(address!("0x307AF7d28AfEE82092aA95D35644898311CA5360")),
                None
            )),
            expected_digest
        );

        let signer = DynSigner::from_signing_key(
            "0x44a8f44ef7307087c960f8bfcbd95f7a1c9a2f505d438d1750dc947cfedb4b4a",
        )
        .await
        .unwrap();
        user_op.signature = signer.sign_hash(&expected_digest).await.unwrap().as_bytes().into();

        assert_eq!(
            user_op.signature,
            bytes!(
                "0xc48dd8e13f7a09954ff888dc115a9e358c6d8ccc5de8823b7b22242f251ab7333d91ea4e4263e07c60e744dd9f569f4f4b3de4b0ef3949867226a865098769421b"
            )
        );

        assert_eq!(
            Bytes::from(user_op.abi_encode()),
            bytes!(
                "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000e017a867c7204fd596ae3141a5b194596849a196000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c7183455a4c133ae270771860664b6b7ec320bb1000000000000000000000000000000000000000000000000000000003cdf478c000000000000000000000000000000000000000000000000000000003cdf478c000000000000000000000000000000000000000000000000000000000098968000000000000000000000000000000000000000000000000000000000000003600000000000000000000000000000000000000000000000000000000000000380000000000000000000000000000000000000000000000000000000003cdf478c000000000000000000000000000000000000000000000000000000003cdf478c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003a00000000000000000000000000000000000000000000000000000000000000420000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000007fa9385be102ac3eac297483dd6233d62b3e1496000000000000000000000000000000000000000000000000000000009009e8ec000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000443c78f3950000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041c48dd8e13f7a09954ff888dc115a9e358c6d8ccc5de8823b7b22242f251ab7333d91ea4e4263e07c60e744dd9f569f4f4b3de4b0ef3949867226a865098769421b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
    }
}
