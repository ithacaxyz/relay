use super::{IntentV04, IntentV05, SignedCall, SignedCalls, Transfer};
use crate::{
    error::{IntentError, MerkleError},
    signers::Eip712PayLoadSigner,
    types::{IntentKind, Key, LazyMerkleTree, OrchestratorContract, Signature},
};
use alloy::{
    dyn_abi::TypedData,
    primitives::{Address, B256, Bytes, U256},
    providers::DynProvider,
    sol_types::{SolCall, SolValue},
};
use serde::{Deserialize, Serialize};

/// Intent enum with versioned variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Intent {
    /// Version 0.5 of the Intent struct.
    V05(IntentV05),
    /// Version 0.4 of the Intent struct.
    V04(IntentV04),
}

impl Intent {
    /// Creates a new Intent using the latest version.
    pub fn latest() -> Self {
        Self::V05(IntentV05::default())
    }

    /// Creates a new Intent based on the orchestrator version.
    ///
    /// - Orchestrator version >= 0.5.0 creates V05 Intent
    /// - Orchestrator version < 0.5.0 creates V04 Intent
    pub fn for_orchestrator(version: &semver::Version) -> Self {
        if *version >= semver::Version::new(0, 5, 0) { Self::v05() } else { Self::v04() }
    }

    /// Creates a new v04 Intent.
    pub fn v04() -> Self {
        Self::V04(IntentV04::default())
    }

    /// Creates a new v05 Intent.
    pub fn v05() -> Self {
        Self::V05(IntentV05::default())
    }

    // Builder pattern setters (with_ prefix)

    /// Sets the user's address.
    pub fn with_eoa(mut self, eoa: Address) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.eoa = eoa,
            Intent::V04(intent) => intent.eoa = eoa,
        }
        self
    }

    /// Sets the execution data - an encoded array of calls, using ERC7579 batch execution encoding.
    pub fn with_execution_data(mut self, execution_data: Bytes) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.executionData = execution_data,
            Intent::V04(intent) => intent.executionData = execution_data,
        }
        self
    }

    /// Sets the nonce per delegated EOA.
    pub fn with_nonce(mut self, nonce: U256) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.nonce = nonce,
            Intent::V04(intent) => intent.nonce = nonce,
        }
        self
    }

    /// Sets the account paying the payment token.
    pub fn with_payer(mut self, payer: Address) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.payer = payer,
            Intent::V04(intent) => intent.payer = payer,
        }
        self
    }

    /// Sets the ERC20 or native token used to pay for gas.
    pub fn with_payment_token(mut self, payment_token: Address) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.paymentToken = payment_token,
            Intent::V04(intent) => intent.paymentToken = payment_token,
        }
        self
    }

    /// Sets the amount of the token to pay, before the call batch is executed.
    pub fn with_pre_payment_max_amount(mut self, amount: U256) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.paymentMaxAmount = amount,
            Intent::V04(intent) => intent.prePaymentMaxAmount = amount,
        }
        self
    }

    /// Sets the maximum amount of the token to pay.
    pub fn with_total_payment_max_amount(mut self, amount: U256) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.paymentMaxAmount = amount,
            Intent::V04(intent) => intent.totalPaymentMaxAmount = amount,
        }
        self
    }

    /// Sets the combined gas limit for payment, verification, and calling the EOA.
    pub fn with_combined_gas(mut self, gas: U256) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.combinedGas = gas,
            Intent::V04(intent) => intent.combinedGas = gas,
        }
        self
    }

    /// Sets the encoded pre-calls array.
    pub fn with_encoded_pre_calls(mut self, pre_calls: Vec<Bytes>) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.encodedPreCalls = pre_calls,
            Intent::V04(intent) => intent.encodedPreCalls = pre_calls,
        }
        self
    }

    /// Sets the encoded fund transfers array.
    pub fn with_encoded_fund_transfers(mut self, transfers: Vec<Bytes>) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.encodedFundTransfers = transfers,
            Intent::V04(intent) => intent.encodedFundTransfers = transfers,
        }
        self
    }

    /// Sets the settler address.
    pub fn with_settler(mut self, settler: Address) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.settler = settler,
            Intent::V04(intent) => intent.settler = settler,
        }
        self
    }

    /// Sets the expiry timestamp for the intent.
    pub fn with_expiry(mut self, expiry: U256) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.expiry = expiry,
            Intent::V04(intent) => intent.expiry = expiry,
        }
        self
    }

    /// Sets the intent as interop/multichain.
    pub fn with_interop(mut self) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.isMultichain = true,
            Intent::V04(intent) => intent.isMultichain = true,
        }
        self
    }

    /// Sets the funder address.
    pub fn with_funder(mut self, funder: Address) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.funder = funder,
            Intent::V04(intent) => intent.funder = funder,
        }
        self
    }

    /// Sets the funder signature.
    pub fn with_funder_signature(mut self, signature: Bytes) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.funderSignature = signature,
            Intent::V04(intent) => intent.funderSignature = signature,
        }
        self
    }

    /// Sets the settler context data.
    pub fn with_settler_context(mut self, context: Bytes) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.settlerContext = context,
            Intent::V04(intent) => intent.settlerContext = context,
        }
        self
    }

    /// Sets the actual pre payment amount.
    pub fn with_pre_payment_amount(mut self, amount: U256) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.paymentAmount = amount,
            Intent::V04(intent) => intent.prePaymentAmount = amount,
        }
        self
    }

    /// Sets the actual total payment amount.
    pub fn with_total_payment_amount(mut self, amount: U256) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.paymentAmount = amount,
            Intent::V04(intent) => intent.totalPaymentAmount = amount,
        }
        self
    }

    /// Sets the payment recipient for the ERC20 token.
    pub fn with_payment_recipient(mut self, recipient: Address) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.paymentRecipient = recipient,
            Intent::V04(intent) => intent.paymentRecipient = recipient,
        }
        self
    }

    /// Sets the wrapped signature.
    pub fn with_signature(mut self, signature: Bytes) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.signature = signature,
            Intent::V04(intent) => intent.signature = signature,
        }
        self
    }

    /// Sets the payment signature.
    pub fn with_payment_signature(mut self, signature: Bytes) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.paymentSignature = signature,
            Intent::V04(intent) => intent.paymentSignature = signature,
        }
        self
    }

    /// Sets the supported account implementation.
    pub fn with_supported_account_implementation(mut self, implementation: Address) -> Self {
        match &mut self {
            Intent::V05(intent) => intent.supportedAccountImplementation = implementation,
            Intent::V04(intent) => intent.supportedAccountImplementation = implementation,
        }
        self
    }

    // Mutable accessor for payment recipient

    /// Sets the payment recipient.
    pub fn set_payment_recipient(&mut self, recipient: Address) {
        match self {
            Intent::V05(intent) => intent.paymentRecipient = recipient,
            Intent::V04(intent) => intent.paymentRecipient = recipient,
        }
    }

    // Getters with documentation

    /// The user's address.
    pub fn eoa(&self) -> &Address {
        match self {
            Intent::V05(intent) => &intent.eoa,
            Intent::V04(intent) => &intent.eoa,
        }
    }

    /// An encoded array of calls, using ERC7579 batch execution encoding.
    ///
    /// The format is `abi.encode(calls)`, where `calls` is an array of type `Call[]`.
    ///
    /// This allows for more efficient safe forwarding to the EOA.
    pub fn execution_data(&self) -> &Bytes {
        match self {
            Intent::V05(intent) => &intent.executionData,
            Intent::V04(intent) => &intent.executionData,
        }
    }

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
    pub fn nonce(&self) -> U256 {
        match self {
            Intent::V05(intent) => intent.nonce,
            Intent::V04(intent) => intent.nonce,
        }
    }

    /// The account paying the payment token.
    ///
    /// If this is `address(0)`, it defaults to the `eoa`.
    pub fn payer(&self) -> Address {
        match self {
            Intent::V05(intent) => intent.payer,
            Intent::V04(intent) => intent.payer,
        }
    }

    /// The ERC20 or native token used to pay for gas.
    pub fn payment_token(&self) -> Address {
        match self {
            Intent::V05(intent) => intent.paymentToken,
            Intent::V04(intent) => intent.paymentToken,
        }
    }

    /// The amount of the token to pay, before the call batch is executed
    /// This will be required to be less than `totalPaymentMaxAmount`.
    pub fn pre_payment_max_amount(&self) -> U256 {
        match self {
            Intent::V05(intent) => intent.paymentMaxAmount,
            Intent::V04(intent) => intent.prePaymentMaxAmount,
        }
    }

    /// The maximum amount of the token to pay.
    pub fn total_payment_max_amount(&self) -> U256 {
        match self {
            Intent::V05(intent) => intent.paymentMaxAmount,
            Intent::V04(intent) => intent.totalPaymentMaxAmount,
        }
    }

    /// The combined gas limit for payment, verification, and calling the EOA.
    pub fn combined_gas(&self) -> U256 {
        match self {
            Intent::V05(intent) => intent.combinedGas,
            Intent::V04(intent) => intent.combinedGas,
        }
    }

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
    pub fn encoded_pre_calls(&self) -> &Vec<Bytes> {
        match self {
            Intent::V05(intent) => &intent.encodedPreCalls,
            Intent::V04(intent) => &intent.encodedPreCalls,
        }
    }

    /// Only relevant for multi chain intents.
    pub fn encoded_fund_transfers(&self) -> &Vec<Bytes> {
        match self {
            Intent::V05(intent) => &intent.encodedFundTransfers,
            Intent::V04(intent) => &intent.encodedFundTransfers,
        }
    }

    /// The settler address.
    pub fn settler(&self) -> Address {
        match self {
            Intent::V05(intent) => intent.settler,
            Intent::V04(intent) => intent.settler,
        }
    }

    /// The expiry timestamp for the intent. The intent is invalid after this timestamp.
    /// If expiry timestamp is set to 0, then expiry is considered to be infinite.
    pub fn expiry(&self) -> U256 {
        match self {
            Intent::V05(intent) => intent.expiry,
            Intent::V04(intent) => intent.expiry,
        }
    }

    /// Whether the intent is marked as interop/multichain via the isMultichain field.
    pub fn is_interop(&self) -> bool {
        match self {
            Intent::V05(intent) => intent.isMultichain,
            Intent::V04(intent) => intent.isMultichain,
        }
    }

    /// Whether the intent has a multichain nonce prefix.
    ///
    /// Checks if the nonce has the MULTICHAIN_NONCE_PREFIX in the upper 16 bits.
    pub fn is_nonce_multichain(&self) -> bool {
        SignedCalls::is_multichain(self)
    }

    /// The funder address.
    pub fn funder(&self) -> Address {
        match self {
            Intent::V05(intent) => intent.funder,
            Intent::V04(intent) => intent.funder,
        }
    }

    /// The funder signature.
    pub fn funder_signature(&self) -> &Bytes {
        match self {
            Intent::V05(intent) => &intent.funderSignature,
            Intent::V04(intent) => &intent.funderSignature,
        }
    }

    /// Context data passed to the settler for processing attestations.
    ///
    /// This data is ABI-encoded and contains information needed by the settler
    /// to process the multichain intent (e.g., list of chain IDs).
    pub fn settler_context(&self) -> &Bytes {
        match self {
            Intent::V05(intent) => &intent.settlerContext,
            Intent::V04(intent) => &intent.settlerContext,
        }
    }

    /// The actual pre payment amount, requested by the filler. MUST be less than or equal to
    /// `prePaymentMaxAmount`
    pub fn pre_payment_amount(&self) -> U256 {
        match self {
            Intent::V05(intent) => intent.paymentAmount,
            Intent::V04(intent) => intent.prePaymentAmount,
        }
    }

    /// The actual total payment amount, requested by the filler. MUST be less than or equal to
    /// `totalPaymentMaxAmount`
    pub fn total_payment_amount(&self) -> U256 {
        match self {
            Intent::V05(intent) => intent.paymentAmount,
            Intent::V04(intent) => intent.totalPaymentAmount,
        }
    }

    /// The payment recipient for the ERC20 token.
    /// Excluded from signature. The filler can replace this with their own address.
    /// This enables multiple fillers, allowing for competitive filling, better uptime.
    pub fn payment_recipient(&self) -> Address {
        match self {
            Intent::V05(intent) => intent.paymentRecipient,
            Intent::V04(intent) => intent.paymentRecipient,
        }
    }

    /// The wrapped signature.
    /// `abi.encodePacked(innerSignature, keyHash, prehash)`.
    pub fn signature(&self) -> &Bytes {
        match self {
            Intent::V05(intent) => &intent.signature,
            Intent::V04(intent) => &intent.signature,
        }
    }

    /// Optional payment signature to be passed into the `compensate` function
    /// on the `payer`. This signature is NOT included in the EIP712 signature.
    pub fn payment_signature(&self) -> &Bytes {
        match self {
            Intent::V05(intent) => &intent.paymentSignature,
            Intent::V04(intent) => &intent.paymentSignature,
        }
    }

    /// Optional. If non-zero, the EOA must use `supportedAccountImplementation`.
    /// Otherwise, if left as `address(0)`, any EOA implementation will be supported.
    /// This field is NOT included in the EIP712 signature.
    pub fn supported_account_implementation(&self) -> Address {
        match self {
            Intent::V05(intent) => intent.supportedAccountImplementation,
            Intent::V04(intent) => intent.supportedAccountImplementation,
        }
    }

    // Pass-through methods to underlying implementation

    /// Sets payment amount and max specified amount.
    pub fn set_payment(&mut self, amount: U256) {
        match self {
            Intent::V05(intent) => {
                intent.paymentMaxAmount = amount;
                intent.paymentAmount = amount;
            }
            Intent::V04(intent) => {
                intent.prePaymentAmount = amount;
                intent.prePaymentMaxAmount = amount;
                intent.totalPaymentAmount = amount;
                intent.totalPaymentMaxAmount = amount;
            }
        }
    }

    /// Calculate a digest of the [`Intent`], used for checksumming.
    pub fn digest(&self) -> B256 {
        match self {
            Intent::V05(intent) => intent.digest(),
            Intent::V04(intent) => intent.digest(),
        }
    }

    /// Returns all keys authorized in `pre_calls`.
    pub fn pre_authorized_keys(&self) -> Result<Vec<Key>, alloy::sol_types::Error> {
        let mut all_keys = Vec::with_capacity(self.encoded_pre_calls().len());
        for encoded_precall in self.encoded_pre_calls() {
            let pre_call = SignedCall::abi_decode(encoded_precall)?;
            all_keys.extend(pre_call.authorized_keys_from_execution_data()?);
        }
        Ok(all_keys)
    }

    /// Returns all fund transfers in the intent.
    pub fn fund_transfers(&self) -> Result<Vec<(Address, U256)>, alloy::sol_types::Error> {
        self.encoded_fund_transfers()
            .iter()
            .map(|transfer| {
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
    pub async fn with_mock_merkle_signature<S: Eip712PayLoadSigner>(
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
        self = self.with_signature((proof, root, signature).abi_encode_params().into());

        Ok(self)
    }
}

impl Default for Intent {
    fn default() -> Self {
        Self::V05(IntentV05::default())
    }
}

impl SignedCalls for Intent {
    fn execution_data(&self) -> &[u8] {
        match self {
            Intent::V05(intent) => intent.execution_data(),
            Intent::V04(intent) => intent.execution_data(),
        }
    }

    fn nonce(&self) -> U256 {
        match self {
            Intent::V05(intent) => intent.nonce(),
            Intent::V04(intent) => intent.nonce(),
        }
    }

    async fn compute_eip712_data(
        &self,
        orchestrator_address: Address,
        provider: &DynProvider,
    ) -> eyre::Result<(B256, alloy::dyn_abi::TypedData)>
    where
        Self: Sync,
    {
        match self {
            Intent::V05(intent) => intent.compute_eip712_data(orchestrator_address, provider).await,
            Intent::V04(intent) => intent.compute_eip712_data(orchestrator_address, provider).await,
        }
    }

    fn authorized_keys(&self) -> Result<Vec<Key>, alloy::sol_types::Error> {
        match self {
            Intent::V05(intent) => intent.authorized_keys(),
            Intent::V04(intent) => intent.authorized_keys(),
        }
    }
}

// Intent-specific methods that delegate to the underlying version
impl Intent {
    /// Get the ABI-encoded bytes of the intent.
    pub fn abi_encode(&self) -> Vec<u8> {
        match self {
            Intent::V05(intent) => intent.abi_encode(),
            Intent::V04(intent) => intent.abi_encode(),
        }
    }

    /// Get the ABI-encoded packed bytes of the intent.
    pub fn abi_encode_packed(&self) -> Vec<u8> {
        match self {
            Intent::V05(intent) => intent.abi_encode_packed(),
            Intent::V04(intent) => intent.abi_encode_packed(),
        }
    }

    /// Get the inner IntentV04 reference.
    pub fn as_v04(&self) -> Option<&IntentV04> {
        match self {
            Intent::V04(intent) => Some(intent),
            _ => None,
        }
    }

    /// Get the inner IntentV05 reference.
    pub fn as_v05(&self) -> Option<&IntentV05> {
        match self {
            Intent::V05(intent) => Some(intent),
            _ => None,
        }
    }

    /// Get mutable access to the inner IntentV04.
    pub fn as_v04_mut(&mut self) -> Option<&mut IntentV04> {
        match self {
            Intent::V04(intent) => Some(intent),
            _ => None,
        }
    }

    /// Get mutable access to the inner IntentV05.
    pub fn as_v05_mut(&mut self) -> Option<&mut IntentV05> {
        match self {
            Intent::V05(intent) => Some(intent),
            _ => None,
        }
    }

    /// Get the TypedData representation of the intent with a domain.
    pub fn typed_data(&self, domain: Option<alloy::dyn_abi::Eip712Domain>) -> TypedData {
        match self {
            Intent::V05(intent) => TypedData::from_struct(intent, domain),
            Intent::V04(intent) => TypedData::from_struct(intent, domain),
        }
    }
}
