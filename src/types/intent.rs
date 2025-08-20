use super::{
    Call, IDelegation::authorizeCall, Key, LazyMerkleTree, MerkleLeafInfo, OrchestratorContract,
};
use crate::{
    error::{IntentError, MerkleError},
    types::{
        CallPermission,
        IthacaAccount::{setCanExecuteCall, setSpendLimitCall},
        Orchestrator, Signature,
        rpc::{
            AddressOrNative, AuthorizeKey, AuthorizeKeyResponse, BalanceOverrides, Permission,
            SpendPermission,
        },
    },
};
use alloy::{
    dyn_abi::TypedData,
    eips::eip7702::SignedAuthorization,
    primitives::{
        Address, B256, Bytes, ChainId, Keccak256, U256, aliases::U192, keccak256, map::HashMap,
    },
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
    /// A struct to hold the intent fields.
    ///
    /// Since L2s already include calldata compression with savings forwarded to users,
    /// we don't need to be too concerned about calldata overhead.
    #[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Intent {
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
        /// of the Intent will exlude the chain ID.
        ///
        /// # Ordering
        ///
        /// Ordering matters within a sequence key, but not between sequence keys.
        ///
        /// This means that users who do not care about the order of specific intents
        /// can sign their intents using a random sequence key. On the other hand, if
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
        /// Optional array of encoded Intents that will be verified and executed
        /// after PREP (if any) and before the validation of the overall Intent.
        /// A PreCall will NOT have its gas limit or payment applied.
        /// The overall Intent's gas limit and payment will be applied, encompassing all its PreCalls.
        /// The execution of a PreCall will check and increment the nonce in the PreCall.
        /// If at any point, any PreCall cannot be verified to be correct, or fails in execution,
        /// the overall Intent will revert before validation, and execute will return a non-zero error.
        /// A PreCall can contain PreCalls, forming a tree structure.
        /// The `executionData` tree will be executed in post-order (i.e. left -> right -> current).
        /// The `encodedPreCalls` are included in the EIP712 signature, which enables execution order
        /// to be enforced on-the-fly even if the nonces are from different sequences.
        bytes[] encodedPreCalls;
        /// Only relevant for multi chain intents.
        bytes[] encodedFundTransfers;
        /// The settler address.
        address settler;
        /// The expiry timestamp for the intent. The intent is invalid after this timestamp.
        /// If expiry timestamp is set to 0, then expiry is considered to be infinite.
        uint256 expiry;
        ////////////////////////////////////////////////////////////////////////
        // Additional Fields (Not included in EIP-712)
        ////////////////////////////////////////////////////////////////////////
        /// Whether the intent should use the multichain mode - i.e verify with merkle sigs
        /// and send the cross chain message.
        bool isMultichain;
        /// The funder address.
        address funder;
        /// The funder signature.
        bytes funderSignature;
        /// Context data passed to the settler for processing attestations.
        ///
        /// This data is ABI-encoded and contains information needed by the settler
        /// to process the multichain intent (e.g., list of chain IDs).
        bytes settlerContext;
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
        /// Optional. If non-zero, the EOA must use `supportedAccountImplementation`.
        /// Otherwise, if left as `address(0)`, any EOA implementation will be supported.
        /// This field is NOT included in the EIP712 signature.
        address supportedAccountImplementation;
    }


    /// A struct to hold the fields for a PreCall.
    /// Like a Intent with a subset of fields.
    #[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SignedCall {
        /// The user's address.
        ///
        /// This can be set to `address(0)`, which allows it to be
        /// coalesced to the parent Intent's EOA.
        address eoa;
        /// An encoded array of calls, using ERC7579 batch execution encoding.
        ///
        /// `abi.encode(calls)`, where `calls` is of type `Call[]`.
        /// This allows for more efficient safe forwarding to the EOA.
        bytes executionData;
        /// Per delegated EOA. Same logic as the `nonce` in Intent.
        uint256 nonce;
        /// The wrapped signature.
        ///
        /// `abi.encodePacked(innerSignature, keyHash, prehash)`.
        bytes signature;
    }

    /// A struct to fund an account on an output chain from a multi chain intent.
    #[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Transfer {
        address token;
        uint256 amount;
    }
}

/// A partial [`Intent`] used for fee estimation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartialIntent {
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
    /// Optional payer of the gas.
    pub payer: Option<Address>,
    /// Optional array of encoded PreCalls that will be verified and executed before the
    /// verification of the overall Intent.
    pub pre_calls: Vec<SignedCall>,
    /// Funds required in the destination chain.
    pub fund_transfers: Vec<(Address, U256)>,
}

/// Context for fee estimation that groups execution-related parameters.
#[derive(Debug, Clone)]
pub struct FeeEstimationContext {
    /// The token to use for fee payment.
    pub fee_token: Address,
    /// Optional stored authorization for EIP-7702 delegation.
    pub stored_authorization: Option<SignedAuthorization>,
    /// The account key used for signing.
    pub account_key: Key,
    /// Whether to override key slots in state.
    pub key_slot_override: bool,
    /// The kind of intent being estimated.
    pub intent_kind: IntentKind,
    /// State overrides for simulation.
    pub state_overrides: alloy::rpc::types::state::StateOverride,
    /// Balance overrides for simulation.
    pub balance_overrides: BalanceOverrides,
}

mod eip712 {
    use crate::types::Call;
    use alloy::sol;

    sol! {
        #[derive(serde::Serialize)]
        struct Intent {
            bool multichain;
            address eoa;
            Call[] calls;
            uint256 nonce;
            address payer;
            address paymentToken;
            uint256 prePaymentMaxAmount;
            uint256 totalPaymentMaxAmount;
            uint256 combinedGas;
            bytes[] encodedPreCalls;
            bytes[] encodedFundTransfers;
            address settler;
            uint256 expiry;
        }

        #[derive(serde::Serialize)]
        struct SignedCall {
            bool multichain;
            address eoa;
            Call[] calls;
            uint256 nonce;
        }
    }
}

impl Intent {
    /// Sets the payment amount fields so it has the same behaviour as legacy Intent.
    pub fn set_legacy_payment_amount(&mut self, amount: U256) {
        self.prePaymentAmount = amount;
        self.prePaymentMaxAmount = amount;
        self.totalPaymentAmount = amount;
        self.totalPaymentMaxAmount = amount;
    }

    /// Calculate a digest of the [`Intent`], used for checksumming.
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
        let pre_calls_hash = {
            let mut hasher = Keccak256::new();
            for pre_call in self.encodedPreCalls.iter() {
                hasher.update(keccak256(pre_call));
            }
            hasher.finalize()
        };
        hasher.update(pre_calls_hash);
        for transfer in &self.encodedFundTransfers {
            hasher.update(transfer);
        }
        hasher.update(self.settler);
        hasher.update(self.expiry.to_be_bytes::<32>());
        hasher.update(self.supportedAccountImplementation);
        hasher.finalize()
    }

    /// Returns all keys authorized in `pre_calls`.
    pub fn pre_authorized_keys(&self) -> Result<Vec<Key>, alloy::sol_types::Error> {
        let mut all_keys = Vec::with_capacity(self.encodedPreCalls.len());
        for (idx, encoded_precall) in self.encodedPreCalls.iter().enumerate() {
            tracing::debug!(idx, len = encoded_precall.len(), "decoding precall");
            let pre_call = SignedCall::abi_decode(encoded_precall)?;
            all_keys.extend(pre_call.authorized_keys_from_execution_data()?);
        }
        Ok(all_keys)
    }

    /// Returns all fund transfers in the intent.
    pub fn fund_transfers(&self) -> Result<Vec<(Address, U256)>, alloy::sol_types::Error> {
        self.encodedFundTransfers
            .iter()
            .enumerate()
            .map(|(idx, transfer)| {
                tracing::debug!(idx, len = transfer.len(), "decoding fund transfer");
                let transfer = Transfer::abi_decode(transfer)?;
                Ok((transfer.token, transfer.amount))
            })
            .collect()
    }

    /// Encodes this intent into calldata for [`OrchestratorContract::executeCall`].
    pub fn encode_execute(&self) -> Bytes {
        OrchestratorContract::executeCall { encodedIntent: self.abi_encode().into() }
            .abi_encode()
            .into()
    }

    /// Adds a mocked merkle signature for fee estimation purposes.
    ///
    /// This creates a merkle tree with random leaves except for the current intent's position,
    /// which uses the actual intent hash. It then signs the merkle root and sets the
    /// properly formatted merkle signature on the intent.
    pub async fn with_mock_merkle_signature<S: crate::signers::Eip712PayLoadSigner>(
        mut self,
        intent_kind: &IntentKind,
        orchestrator: Address,
        provider: &DynProvider,
        signer: &S,
        key_hash: B256,
        prehash: bool,
    ) -> Result<Self, IntentError> {
        let leaf_info = intent_kind.merkle_leaf_info()?;

        // Calculate the leaf hash for the current intent
        let (current_leaf_hash, _) = self
            .compute_eip712_data(orchestrator, provider)
            .await
            .map_err(|e| IntentError::from(MerkleError::LeafHashError(e.to_string())))?;

        // Create mock leaves for the merkle tree
        let mut leaves = vec![B256::random(); leaf_info.total];
        leaves[leaf_info.index] = current_leaf_hash;

        // Build the merkle tree
        let mut tree =
            LazyMerkleTree::from_leaves(leaves, leaf_info.total).map_err(IntentError::from)?;
        let root = tree.root().map_err(IntentError::from)?;
        let proof = tree.proof(leaf_info.index).map_err(IntentError::from)?;

        // Sign the merkle root (treating it as if it were an intent digest)
        let signature: Bytes = Signature {
            innerSignature: signer
                .sign_payload_hash(root)
                .await
                .map_err(|e| IntentError::from(MerkleError::LeafHashError(e.to_string())))?,
            keyHash: key_hash,
            prehash,
        }
        .abi_encode_packed()
        .into();

        // Build merkle signature format: (proof, root, signature)
        self.signature = (proof, root, signature).abi_encode_params().into();

        Ok(self)
    }
}

impl SignedCall {
    /// Returns all authorized keys with their permissions.
    pub fn authorized_keys_with_permissions(
        &self,
    ) -> Result<Vec<AuthorizeKeyResponse>, alloy::sol_types::Error> {
        let mut permissions: HashMap<B256, Vec<Permission>> = HashMap::default();

        for (idx, call) in self.calls()?.into_iter().enumerate() {
            tracing::debug!(idx, len = call.data.len(), "checking permission call");
            // try decoding as a setSpendLimit call first.
            if let Ok(setSpendLimitCall { keyHash, token, period, limit }) =
                setSpendLimitCall::abi_decode(&call.data)
            {
                permissions
                    .entry(keyHash)
                    .or_default()
                    .push(SpendPermission { limit, period, token }.into());
                continue;
            }

            // if it wasn't a setSpendLimit, try decoding as a setCanExecute.
            if let Ok(setCanExecuteCall { keyHash, target: to, fnSel: selector, can }) =
                setCanExecuteCall::abi_decode(&call.data)
                && can
            {
                permissions
                    .entry(keyHash)
                    .or_default()
                    .push(CallPermission { selector, to }.into());
            }
        }

        Ok(self
            .authorized_keys()?
            .into_iter()
            .map(|key| {
                let hash = key.key_hash();
                AuthorizeKeyResponse {
                    authorize_key: AuthorizeKey {
                        permissions: permissions.remove(&hash).unwrap_or_default(),
                        key,
                    },
                    hash,
                }
            })
            .collect())
    }
}

/// Shared behaviour between [`Intent`] and [`PreCall`].
pub trait SignedCalls {
    /// Returns `executionData`.
    fn execution_data(&self) -> &[u8];

    /// Returns `nonce`.
    fn nonce(&self) -> U256;

    /// Returns the decoded calls from `executionData`.
    fn calls(&self) -> Result<Vec<Call>, alloy::sol_types::Error> {
        let data = self.execution_data();
        tracing::debug!(len = data.len(), "decoding execution data");
        <Vec<Call>>::abi_decode(data)
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

    /// Returns all keys authorized in the current intent.
    fn authorized_keys(&self) -> Result<Vec<Key>, alloy::sol_types::Error> {
        Ok(self.authorized_keys_from_execution_data()?.collect())
    }

    /// Whether this intent is multichain.
    ///
    /// If the intent is multichain, the EIP712 domain used for the signing hash of the intent
    /// should not include a chain ID.
    fn is_multichain(&self) -> bool {
        self.nonce() >> 240 == MULTICHAIN_NONCE_PREFIX
    }

    /// Get the EIP712 encoding of the intent.
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

impl SignedCalls for SignedCall {
    fn execution_data(&self) -> &[u8] {
        &self.executionData
    }

    fn nonce(&self) -> U256 {
        self.nonce
    }

    fn as_eip712(&self) -> Result<impl SolStruct + Serialize + Send, alloy::sol_types::Error> {
        Ok(eip712::SignedCall {
            multichain: self.is_multichain(),
            eoa: self.eoa,
            calls: self.calls()?,
            nonce: self.nonce,
        })
    }
}

impl SignedCalls for Intent {
    fn as_eip712(&self) -> Result<impl SolStruct + Serialize + Send, alloy::sol_types::Error> {
        Ok(eip712::Intent {
            multichain: self.is_multichain(),
            eoa: self.eoa,
            calls: self.calls()?,
            nonce: self.nonce,
            payer: self.payer,
            paymentToken: self.paymentToken,
            prePaymentMaxAmount: self.prePaymentMaxAmount,
            totalPaymentMaxAmount: self.totalPaymentMaxAmount,
            combinedGas: self.combinedGas,
            encodedPreCalls: self.encodedPreCalls.clone(),
            encodedFundTransfers: self.encodedFundTransfers.clone(),
            settler: self.settler,
            expiry: self.expiry,
        })
    }

    fn execution_data(&self) -> &[u8] {
        &self.executionData
    }

    fn nonce(&self) -> U256 {
        self.nonce
    }

    /// Returns all keys authorized in the current [`Intent`] including `pre_calls` and
    /// `executionData`.
    fn authorized_keys(&self) -> Result<Vec<Key>, alloy::sol_types::Error> {
        Ok(self.authorized_keys_from_execution_data()?.chain(self.pre_authorized_keys()?).collect())
    }
}

/// Kind of intent to be simulated and created.
#[derive(Debug, Clone)]
pub enum IntentKind {
    /// Single chain intent.
    Single,
    /// Output of a multi chain intent.
    MultiOutput {
        /// The leaf index in the merkle tree.
        leaf_index: usize,
        /// Fund transfers (token address, amount) pairs.
        fund_transfers: Vec<(Address, U256)>,
        /// Settler context (ABI encoded).
        settler_context: Bytes,
    },
    /// Input of a multi chain intent.
    MultiInput {
        /// The merkle leaf information.
        leaf_info: MerkleLeafInfo,
        /// The fee to pay, if precomputed as `(token address, amount)`. If this is `None`, the
        /// fee will be estimated as normal.
        fee: Option<(Address, U256)>,
    },
}

impl IntentKind {
    /// Returns `true` if this is [`IntentKind::Single`].
    pub fn is_single(&self) -> bool {
        matches!(self, IntentKind::Single)
    }

    /// Returns `true` if this is [`IntentKind::MultiOutput`].
    pub fn is_multi_output(&self) -> bool {
        matches!(self, IntentKind::MultiOutput { .. })
    }

    /// Returns `true` if this is [`IntentKind::MultiInput`].
    pub fn is_multi_input(&self) -> bool {
        matches!(self, IntentKind::MultiInput { .. })
    }

    /// Returns the fund transfers if dealing with a multi chain intent.
    pub fn fund_transfers(&self) -> Vec<(Address, U256)> {
        match self {
            IntentKind::MultiOutput { fund_transfers, .. } => fund_transfers.clone(),
            _ => vec![],
        }
    }

    /// Returns the fee for a multichain input if it is set.
    pub fn multi_input_fee(&self) -> Option<U256> {
        match self {
            IntentKind::MultiInput { fee: Some((_, amount)), .. } => Some(*amount),
            _ => None,
        }
    }

    /// Returns the settler context if this is a MultiOutput intent.
    pub fn settler_context(&self) -> Bytes {
        match self {
            IntentKind::MultiOutput { settler_context, .. } => settler_context.clone(),
            _ => Bytes::default(),
        }
    }

    /// Returns the merkle leaf information for multichain intents.
    ///
    /// Returns an error for single chain intents.
    pub fn merkle_leaf_info(&self) -> Result<MerkleLeafInfo, IntentError> {
        match self {
            IntentKind::MultiOutput { leaf_index, .. } => {
                Ok(MerkleLeafInfo { total: *leaf_index + 1, index: *leaf_index })
            }
            IntentKind::MultiInput { leaf_info, .. } => Ok(*leaf_info),
            IntentKind::Single => Err(IntentError::from(MerkleError::LeafHashError(
                "Cannot build merkle tree for single chain intent".to_string(),
            ))),
        }
    }
}

/// Context for building a funding intent in multichain operations.
#[derive(Debug, Clone)]
pub struct FundingIntentContext {
    /// The EOA that will escrow funds
    pub eoa: Address,
    /// The chain where funds will be escrowed
    pub chain_id: ChainId,
    /// The asset to be escrowed (native or ERC20)
    pub asset: AddressOrNative,
    /// The amount to escrow
    pub amount: U256,
    /// The fee token to use for gas payment
    pub fee_token: Address,
    /// The output intent digest this funding will support
    pub output_intent_digest: B256,
    /// The destination chain ID where funds will be used
    pub output_chain_id: ChainId,
}

/// A funding source.
///
/// A funding source is an amount of assets on a specific chain, and an associated cost with using
/// those funds.
#[derive(Debug, Clone)]
pub struct FundSource {
    /// The chain ID the funds are on.
    pub chain_id: ChainId,
    /// The amount of funds on that chain.
    pub amount: U256,
    /// The address of the funds.
    ///
    /// # Note
    ///
    /// This can (and probably will!) differ from chain to chain.
    pub address: Address,
    /// The cost of transferring the funds.
    ///
    /// The cost is in base units of the funds we are trying to transfer; in the future, we may
    /// want to separate this out.
    pub cost: U256,
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
        assert!(!Intent::default().is_multichain());
        assert!(
            Intent { nonce: U256::from(MULTICHAIN_NONCE_PREFIX << 240), ..Default::default() }
                .is_multichain()
        );
        assert!(
            Intent {
                nonce: (MULTICHAIN_NONCE_PREFIX << 240) | U256::from(31338),
                ..Default::default()
            }
            .is_multichain()
        )
    }

    #[test]
    fn intent_eip712_digest() {
        let mut intent = Intent {
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
            encodedPreCalls: vec![],
            encodedFundTransfers: vec![bytes!("")],
            settler: Address::ZERO,
            expiry: U256::ZERO,
            settlerContext: bytes!(""),
            prePaymentAmount: U256::from(3822601006u64),
            totalPaymentAmount: U256::from(3822601006u64),
            paymentRecipient: Address::ZERO,
            signature: bytes!(""),
            paymentSignature: bytes!(""),
            supportedAccountImplementation: Address::ZERO,
            funder: Address::ZERO,
            funderSignature: bytes!(""),
            isMultichain: false,
        };

        // Single chain op
        intent.nonce = U256::from(31338);
        assert_eq!(
            intent.as_eip712().unwrap().eip712_signing_hash(&Eip712Domain::new(
                Some("Orchestrator".into()),
                Some("0.0.1".into()),
                Some(U256::from(31337)),
                Some(address!("0x307AF7d28AfEE82092aA95D35644898311CA5360")),
                None
            )),
            b256!("0x73441b6d0e26f007fe0502197dd6a38ba23390793db0857d44fcb886c1951a73")
        );

        // Multichain op
        intent.nonce = (MULTICHAIN_NONCE_PREFIX << 240) | U256::from(31338);
        assert_eq!(
            intent.as_eip712().unwrap().eip712_signing_hash(&Eip712Domain::new(
                Some("Orchestrator".into()),
                Some("0.0.1".into()),
                None,
                Some(address!("0x307AF7d28AfEE82092aA95D35644898311CA5360")),
                None
            )),
            b256!("0x23525bbb9857ea723c78e0075a63c794c0e6212ca43f5192fb181b5de34a9136")
        );
    }

    #[tokio::test]
    async fn intent_with_signature() {
        let mut intent = Intent {
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
            encodedPreCalls: vec![],
            encodedFundTransfers: vec![bytes!("")],
            settler: Address::ZERO,
            expiry: U256::ZERO,
            settlerContext: bytes!(""),
            prePaymentAmount: U256::from(1021265804),
            totalPaymentAmount: U256::from(1021265804),
            paymentRecipient: Address::ZERO,
            signature: bytes!(""),
            paymentSignature: bytes!(""),
            supportedAccountImplementation: Address::ZERO,
            funder: Address::ZERO,
            funderSignature: bytes!(""),
            isMultichain: false,
        };

        let expected_digest =
            b256!("0x01cdc1e4abcc1e13c42346be0202934a6d29e74a956779e1ea49136ce3f13b70");
        assert_eq!(
            intent.as_eip712().unwrap().eip712_signing_hash(&Eip712Domain::new(
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
        intent.signature = signer.sign_hash(&expected_digest).await.unwrap().as_bytes().into();

        assert_eq!(
            intent.signature,
            bytes!(
                "0x73b4adced3c0df6ad95813d47d1f32d3fd7f9b5da437ebb34d9748b8f64a2a663c938d41f95f4d65014f62caf29b5b7a6123c4166f579dc3d728dc6f6a8521e91b"
            )
        );

        assert_eq!(
            Bytes::from(intent.abi_encode()),
            bytes!(
                "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000e017a867c7204fd596ae3141a5b194596849a19600000000000000000000000000000000000000000000000000000000000002c000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c7183455a4c133ae270771860664b6b7ec320bb1000000000000000000000000000000000000000000000000000000003cdf478c000000000000000000000000000000000000000000000000000000003cdf478c000000000000000000000000000000000000000000000000000000000098968000000000000000000000000000000000000000000000000000000000000004200000000000000000000000000000000000000000000000000000000000000440000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004a000000000000000000000000000000000000000000000000000000000000004c0000000000000000000000000000000000000000000000000000000003cdf478c000000000000000000000000000000000000000000000000000000003cdf478c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004e00000000000000000000000000000000000000000000000000000000000000560000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000007fa9385be102ac3eac297483dd6233d62b3e1496000000000000000000000000000000000000000000000000000000009009e8ec000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000443c78f3950000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004173b4adced3c0df6ad95813d47d1f32d3fd7f9b5da437ebb34d9748b8f64a2a663c938d41f95f4d65014f62caf29b5b7a6123c4166f579dc3d728dc6f6a8521e91b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
    }
}
