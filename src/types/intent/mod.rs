use super::{Call, IDelegation::authorizeCall, Key, MerkleLeafInfo};
use crate::{
    error::{IntentError, MerkleError, RelayError},
    types::{
        CallPermission,
        IthacaAccount::{setCanExecuteCall, setSpendLimitCall, setSpendLimitsEnabledCall},
        KeyType, Orchestrator, Signature, SignedCall,
        rpc::{
            AddressOrNative, AuthorizeKey, AuthorizeKeyResponse, BalanceOverrides, CallKey,
            Permission, SpendPermission,
        },
    },
};
use alloy::{
    dyn_abi::TypedData,
    eips::eip7702::SignedAuthorization,
    primitives::{Address, B256, Bytes, ChainId, U256, aliases::U192, map::HashMap},
    providers::DynProvider,
    sol,
    sol_types::{SolCall, SolStruct, SolValue},
    uint,
};
use serde::{Deserialize, Serialize};
use std::future::Future;

mod r#enum;
mod v04;
mod v05;

pub use r#enum::Intent;
pub use v04::IntentV04;
pub use v05::IntentV05;

/// Nonce prefix to signal that the payload is to be signed with EIP-712 without the chain ID.
pub const MULTICHAIN_NONCE_PREFIX: U256 = uint!(0xc1d0_U256);

/// Nonce prefix to signal that the payload is to be signed with EIP-712 without the chain ID.
pub const MULTICHAIN_NONCE_PREFIX_U192: U192 = uint!(0xc1d0_U192);

sol! {
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
    /// Delegation implementation address.
    pub delegation_implementation: Address,
}

/// Context for fee estimation that groups execution-related parameters.
#[derive(Debug, Clone)]
pub struct FeeEstimationContext {
    /// The token to use for fee payment.
    pub fee_token: Address,
    /// Optional stored authorization for EIP-7702 delegation.
    pub stored_authorization: Option<SignedAuthorization>,
    /// The key that will sign the intent.
    pub key: IntentKey<Key>,
    /// Whether to override key slots in state.
    pub key_slot_override: bool,
    /// The kind of intent being estimated.
    pub intent_kind: IntentKind,
    /// State overrides for simulation.
    pub state_overrides: alloy::rpc::types::state::StateOverride,
    /// Balance overrides for simulation.
    pub balance_overrides: BalanceOverrides,
    /// Whether to calculate asset deficits.
    pub calculate_asset_deficits: bool,
}

impl FeeEstimationContext {
    /// Returns the address of the stored [`SignedAuthorization`].
    pub fn stored_auth_address(&self) -> Option<Address> {
        self.stored_authorization.as_ref().map(|auth| auth.address)
    }
}

mod eip712 {
    use crate::types::Call;
    use alloy::sol;

    sol! {
        #[derive(serde::Serialize)]
        struct SignedCall {
            bool multichain;
            address eoa;
            Call[] calls;
            uint256 nonce;
        }
    }
}

impl SignedCall {
    /// Returns a new SignedCall with the signature set.
    pub fn with_signature(mut self, signature: Bytes) -> Self {
        self.signature = signature;
        self
    }

    /// Returns all authorized keys with their permissions.
    pub fn authorized_keys_with_permissions(
        &self,
    ) -> Result<Vec<AuthorizeKeyResponse>, alloy::sol_types::Error> {
        let mut permissions: HashMap<B256, Vec<Permission>> = HashMap::default();
        let mut spend_permissions_disabled: HashMap<B256, bool> = HashMap::default();

        for call in self.calls()? {
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

            if let Ok(setSpendLimitsEnabledCall { keyHash, enabled }) =
                setSpendLimitsEnabledCall::abi_decode(&call.data)
            {
                spend_permissions_disabled.insert(keyHash, enabled);
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
                        spend_permissions_disabled: spend_permissions_disabled.remove(&hash),
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

    /// Computes the EIP-712 digest that the user must sign.
    fn compute_eip712_data(
        &self,
        orchestrator_address: Address,
        provider: &DynProvider,
    ) -> impl Future<Output = Result<(B256, TypedData), RelayError>> + Send
    where
        Self: Sync;
}

impl SignedCalls for SignedCall {
    fn execution_data(&self) -> &[u8] {
        &self.executionData
    }

    fn nonce(&self) -> U256 {
        self.nonce
    }

    async fn compute_eip712_data(
        &self,
        orchestrator_address: Address,
        provider: &DynProvider,
    ) -> Result<(B256, TypedData), RelayError>
    where
        Self: Sync,
    {
        // Create the orchestrator instance with the same overrides.
        let orchestrator = Orchestrator::new(orchestrator_address, provider);

        // Prepare the EIP-712 payload and domain
        let payload = eip712::SignedCall {
            multichain: self.is_multichain(),
            eoa: self.eoa,
            calls: self.calls()?,
            nonce: self.nonce,
        };
        let domain = orchestrator.eip712_domain(self.is_multichain()).await?;

        // Return the computed signing hash (digest).
        let digest = payload.eip712_signing_hash(&domain);
        let typed_data = TypedData::from_struct(&payload, Some(domain));

        debug_assert_eq!(Ok(digest), typed_data.eip712_signing_hash());

        Ok((digest, typed_data))
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
    /// The destination orchestrator where the settlement will be sent from. This is important for
    /// the settlement system when unlocking funds.
    pub output_orchestrator: Address,
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
    pub amount_source: U256,
    /// The amount of funds on that chain, denominated in the output chain's asset decimals.
    pub amount_destination: U256,
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

/// Intent signer key.
#[derive(Debug, Clone)]
pub enum IntentKey<K> {
    /// EOA root key is signing the intent.
    EoaRootKey,
    /// Custom stored key is signing the intent.
    StoredKey(K),
}

impl<K> IntentKey<K> {
    /// Returns `true` if the key is an EOA root key.
    pub const fn is_eoa_root_key(&self) -> bool {
        matches!(self, IntentKey::EoaRootKey)
    }

    /// Returns a reference to the stored key if it exists.
    pub const fn as_stored_key(&self) -> Option<&K> {
        match self {
            IntentKey::EoaRootKey => None,
            IntentKey::StoredKey(key) => Some(key),
        }
    }

    /// Returns the stored key if it exists.
    pub fn into_stored_key(self) -> Option<K> {
        match self {
            IntentKey::EoaRootKey => None,
            IntentKey::StoredKey(key) => Some(key),
        }
    }
}

impl IntentKey<Key> {
    /// Returns the type of the key used to sign the intent.
    ///
    /// For EOA root key, returns [`KeyType::Secp256k1`].
    pub const fn key_type(&self) -> KeyType {
        match self {
            IntentKey::EoaRootKey => KeyType::Secp256k1,
            IntentKey::StoredKey(key) => key.keyType,
        }
    }

    /// Returns the hash of the key used to sign the intent.
    ///
    /// For EOA root key, returns [`B256::ZERO`].
    pub fn key_hash(&self) -> B256 {
        match self {
            IntentKey::EoaRootKey => B256::ZERO,
            IntentKey::StoredKey(key) => key.key_hash(),
        }
    }

    /// Wraps the provided signature according to [`IntentKey`] type.
    ///
    /// - For [`IntentKey::EoaRootKey`], returns the signature as is.
    /// - For [`IntentKey::StoredKey`], wraps the signature with the key hash and provided prehash
    ///   flag, and ABI encodes it.
    pub fn wrap_signature(&self, signature: Bytes, prehash: bool) -> Bytes {
        match self {
            IntentKey::EoaRootKey => signature,
            IntentKey::StoredKey(key) => {
                Signature { innerSignature: signature, keyHash: key.key_hash(), prehash }
                    .abi_encode_packed()
                    .into()
            }
        }
    }
}

impl IntentKey<CallKey> {
    /// Returns the type of the key used to sign the intent.
    ///
    /// For EOA root key, returns [`KeyType::Secp256k1`].
    pub const fn key_type(&self) -> KeyType {
        match self {
            IntentKey::EoaRootKey => KeyType::Secp256k1,
            IntentKey::StoredKey(key) => key.key_type,
        }
    }

    /// Returns the hash of the key used to sign the intent.
    ///
    /// For EOA root key, returns [`B256::ZERO`].
    pub fn key_hash(&self) -> B256 {
        match self {
            IntentKey::EoaRootKey => B256::ZERO,
            IntentKey::StoredKey(key) => key.key_hash(),
        }
    }

    /// Returns whether the digest will be prehashed by the key.
    ///
    /// For EOA root key, returns `false`.
    pub fn prehash(&self) -> bool {
        match self {
            IntentKey::EoaRootKey => false,
            IntentKey::StoredKey(key) => key.prehash,
        }
    }

    /// Wraps the provided signature according to [`IntentKey`] type.
    ///
    /// - For [`IntentKey::EoaRootKey`], returns the signature as is.
    /// - For [`IntentKey::StoredKey`], wraps the signature with the key hash and provided prehash
    ///   flag, and ABI encodes it.
    pub fn wrap_signature(&self, signature: Bytes) -> Bytes {
        match self {
            IntentKey::EoaRootKey => signature,
            IntentKey::StoredKey(key) => Signature {
                innerSignature: signature,
                keyHash: key.key_hash(),
                prehash: key.prehash,
            }
            .abi_encode_packed()
            .into(),
        }
    }
}
