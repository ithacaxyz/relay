//! RPC calls-related request and response types.

use super::{AuthorizeKey, AuthorizeKeyResponse, Meta, RevokeKey};
use crate::{
    error::{IntentError, RelayError},
    types::{
        Account, Asset, AssetDiffs, Call, CreatableAccount, DEFAULT_SEQUENCE_KEY, IERC20, Key,
        KeyType, MULTICHAIN_NONCE_PREFIX_U192, SignedCall, SignedCalls, SignedQuotes,
    },
};
use alloy::{
    consensus::Eip658Value,
    dyn_abi::TypedData,
    primitives::{
        Address, B256, BlockHash, BlockNumber, Bytes, ChainId, TxHash, U256,
        aliases::{B192, U192},
        wrap_fixed_bytes,
    },
    providers::DynProvider,
    rpc::types::{Log, state::StateOverride},
    sol_types::{SolCall, SolEvent},
    uint,
};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};

wrap_fixed_bytes! {
    /// An identifier for a call bundle.
    ///
    /// This is a unique identifier for a call bundle, which is used to track the status of the bundle.
    ///
    /// Clients should treat this as an opaque value and not attempt to parse it.
    pub struct BundleId<32>;
}

/// Key that will be used to sign the call bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallKey {
    /// Type of key.
    #[serde(rename = "type")]
    pub key_type: KeyType,
    /// Public key in encoded form.
    pub public_key: Bytes,
    /// Whether the digest will be prehashed by the key.
    pub prehash: bool,
}

impl CallKey {
    /// The key hash.
    ///
    /// The hash is computed as `keccak256(abi.encode(key.keyType, keccak256(key.publicKey)))`.
    pub fn key_hash(&self) -> B256 {
        Key::hash(self.key_type, &self.public_key)
    }
}

/// Request parameters for `wallet_prepareCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCallsParameters {
    /// Call bundle to prepare.
    pub calls: Vec<Call>,
    /// Target chain ID.
    #[serde(with = "alloy::serde::quantity")]
    pub chain_id: ChainId,
    /// Address of the account to prepare the call bundle for. It can only be None, if we are
    /// handling a precall
    pub from: Option<Address>,
    /// Request capabilities.
    pub capabilities: PrepareCallsCapabilities,
    /// State overrides for simulating the call bundle.
    ///
    /// This will only be applied to the intent on the output chain in multichain intents.
    #[serde(default)]
    pub state_overrides: StateOverride,
    /// Key that will be used to sign the call bundle. It can only be None, if we are handling a
    /// precall.
    #[serde(default)]
    pub key: Option<CallKey>,
    /// Required funds on the target chain.
    pub required_funds: Vec<(Address, U256)>,
}

impl PrepareCallsParameters {
    /// Ensures there are only whitelisted calls in precalls and that any upgrade delegation request
    /// contains the latest delegation address.
    pub fn check_calls(&self, latest_delegation: Address) -> Result<(), RelayError> {
        let has_unallowed = |calls: &[Call]| -> Result<bool, RelayError> {
            for call in calls {
                if !call.is_whitelisted_precall(self.from.unwrap_or_default(), latest_delegation)? {
                    return Ok(true);
                }
            }
            Ok(false)
        };

        if self.capabilities.pre_call {
            // Ensure this precall request only has valid calls
            if has_unallowed(&self.calls)? {
                return Err(IntentError::UnallowedPreCall.into());
            }
        } else {
            // Ensure that if the intent is upgrading its delegation, it's to the latest one.
            for call in &self.calls {
                call.ensure_valid_upgrade(latest_delegation)?;
            }
        }

        // Ensure precalls only have valid calls
        for precall in &self.capabilities.pre_calls {
            if has_unallowed(&precall.calls().map_err(RelayError::from)?)? {
                return Err(IntentError::UnallowedPreCall.into());
            }
        }

        Ok(())
    }

    /// Retrieves the appropriate nonce for the request, following this order:
    ///
    /// 1. If `capabilities.meta.nonce` is set, return it directly.
    /// 2. If this is a precall, generate a random sequence key without the multichain prefix and
    ///    return its 0th nonce.
    /// 3. If this is a intent and there are any previous precall entries with the
    ///    `DEFAULT_SEQUENCE_KEY`, take the highest nonce and increment it by 1.
    /// 4. If this is the intent of a non delegated account (`maybe_stored`), return random.
    /// 5. If none of the above match, query for the next account nonce onchain (for
    ///    `DEFAULT_SEQUENCE_KEY`).
    pub async fn get_nonce(
        &self,
        maybe_stored: Option<&CreatableAccount>,
        provider: &DynProvider,
    ) -> Result<U256, RelayError> {
        // Create a random sequence key.
        let random_nonce = loop {
            let sequence_key = U192::from_be_bytes(B192::random().into());
            if sequence_key >> 176 != MULTICHAIN_NONCE_PREFIX_U192 {
                break U256::from(sequence_key) << 64;
            }
        };

        if let Some(nonce) = self.capabilities.meta.nonce {
            Ok(nonce)
        } else if self.capabilities.pre_call {
            Ok(random_nonce)
        } else if let Some(precall) = self
            .capabilities
            .pre_calls
            .iter()
            .filter(|precall| (precall.nonce >> 64) == U256::from(DEFAULT_SEQUENCE_KEY))
            .max_by_key(|precall| precall.nonce)
        {
            Ok(precall.nonce + uint!(1_U256))
        } else if maybe_stored.is_some() {
            Ok(random_nonce)
        } else {
            let eoa = self.from.ok_or(IntentError::MissingSender)?;
            Account::new(eoa, &provider).get_nonce().await.map_err(RelayError::from)
        }
    }

    /// Return a self that will be used as a funding intent
    pub fn build_funding_intent(
        eoa: Address,
        chain_id: ChainId,
        funding_asset: Asset,
        amount: U256,
        fee_token: Address,
        request_key: CallKey,
    ) -> Self {
        // todo: escrow
        let escrow = Address::ZERO;
        let escrow_call = if funding_asset.is_native() {
            Call { to: escrow, value: amount, data: Default::default() }
        } else {
            Call {
                to: funding_asset.address(),
                value: U256::ZERO,
                data: IERC20::transferCall { to: escrow, amount }.abi_encode().into(),
            }
        };

        PrepareCallsParameters {
            calls: vec![escrow_call],
            chain_id,
            from: Some(eoa),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                meta: Meta { fee_payer: None, fee_token, nonce: None },
                revoke_keys: vec![],
                pre_calls: vec![],
                pre_call: false,
            },
            state_overrides: Default::default(),
            key: Some(request_key),
            required_funds: vec![],
        }
    }
}

/// Capabilities for `wallet_prepareCalls` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCallsCapabilities {
    /// Keys to authorize on the account.
    #[serde(default)]
    pub authorize_keys: Vec<AuthorizeKey>,
    /// Extra request values.
    pub meta: Meta,
    /// Keys to revoke from the account.
    #[serde(default)]
    pub revoke_keys: Vec<RevokeKey>,
    /// Optional preCalls to execute before signature verification.
    ///
    /// See [`Intent::encodedPreCalls`].
    #[serde(default)]
    pub pre_calls: Vec<SignedCall>,
    /// Whether the call bundle is to be considered a precall.
    #[serde(default)]
    pub pre_call: bool,
}

/// Capabilities for `wallet_prepareCalls` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCallsResponseCapabilities {
    /// Keys that were authorized on the account.
    #[serde(default)]
    pub authorize_keys: Vec<AuthorizeKeyResponse>,
    /// Keys that were revoked from the account.
    #[serde(default)]
    pub revoke_keys: Vec<RevokeKey>,
    /// The [`AssetDiff`] of the prepared call bundle.
    pub asset_diff: AssetDiffs,
}

/// Response for `wallet_prepareCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCallsResponse {
    /// The [`PrepareCallsContext`] of the prepared call bundle.
    pub context: PrepareCallsContext,
    /// Digest of the prepared call bundle for the user to sign over
    /// with an authorized key.
    pub digest: B256,
    /// EIP-712 payload corresponding to the digest.
    pub typed_data: TypedData,
    /// Capabilities response.
    pub capabilities: PrepareCallsResponseCapabilities,
    /// Key that will be used to sign the call bundle.
    #[serde(default)]
    pub key: Option<CallKey>,
}

/// Response context from `wallet_prepareCalls`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum PrepareCallsContext {
    /// The [`SignedQuotes`] of the prepared call bundle.
    #[serde(rename = "quote")]
    Quote(Box<SignedQuotes>),
    /// The [`PreCall`] of the prepared call bundle.
    #[serde(rename = "preCall")]
    PreCall(SignedCall),
}

impl PrepareCallsContext {
    /// Initializes [`PrepareCallsContext`] with [`SignedQuotes`].
    pub fn with_quotes(quote: SignedQuotes) -> Self {
        Self::Quote(Box::new(quote))
    }

    /// Initializes [`PrepareCallsContext`] with a [`PreCall`].
    pub fn with_precall(precall: SignedCall) -> Self {
        Self::PreCall(precall)
    }

    /// Returns quotes immutable reference if it exists.
    pub fn quote(&self) -> Option<&SignedQuotes> {
        match self {
            PrepareCallsContext::Quote(signed) => Some(signed),
            PrepareCallsContext::PreCall(_) => None,
        }
    }

    /// Returns quotes mutable reference if it exists.
    pub fn quote_mut(&mut self) -> Option<&mut SignedQuotes> {
        match self {
            PrepareCallsContext::Quote(signed) => Some(signed),
            PrepareCallsContext::PreCall(_) => None,
        }
    }

    /// Consumes self and returns quotes if it exists.
    pub fn take_quote(self) -> Option<SignedQuotes> {
        match self {
            PrepareCallsContext::Quote(signed) => Some(*signed),
            PrepareCallsContext::PreCall(_) => None,
        }
    }

    /// Consumes self and returns precall if it exists.
    pub fn take_precall(self) -> Option<SignedCall> {
        match self {
            PrepareCallsContext::Quote(_) => None,
            PrepareCallsContext::PreCall(precall) => Some(precall),
        }
    }

    /// Calculate the digest that the user will need to sign.
    ///
    /// It will be a eip712 signing hash in a single chain intent and a merkle root in a multi chain
    /// intent.
    pub async fn compute_signing_digest(
        &self,
        maybe_stored: Option<&CreatableAccount>,
        latest_orchestrator: Address,
        provider: &DynProvider,
    ) -> eyre::Result<(B256, TypedData)> {
        match self {
            PrepareCallsContext::Quote(context) => {
                let output_quote = context.ty().quotes.last().expect("should exist");
                if let Some(root) = context.ty().multi_chain_root {
                    Ok((root, TypedData::from_struct(&output_quote.intent, None)))
                } else {
                    output_quote
                        .intent
                        .compute_eip712_data(output_quote.orchestrator, provider)
                        .await
                }
            }
            PrepareCallsContext::PreCall(pre_call) => {
                let orchestrator_address = if pre_call.eoa == Address::ZERO {
                    // EOA is unknown so we assume that latest orchestrator should be used
                    latest_orchestrator
                } else {
                    // fetch orchestrator address from the account
                    Account::new(pre_call.eoa, provider)
                        .with_delegation_override_opt(
                            maybe_stored.map(|acc| &acc.signed_authorization.address),
                        )
                        .get_orchestrator()
                        .await
                        .map_err(RelayError::from)?
                };

                pre_call.compute_eip712_data(orchestrator_address, provider).await
            }
        }
    }
}

/// Capabilities for `wallet_sendPreparedCalls` request.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SendPreparedCallsCapabilities {
    /// Fee payment signature.
    #[serde(default)]
    pub fee_signature: Bytes,
}

/// Request parameters for `wallet_sendPreparedCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendPreparedCallsParameters {
    /// The [`SendPreparedCallsCapabilities`] of the prepared call bundle.
    #[serde(default)]
    pub capabilities: SendPreparedCallsCapabilities,
    /// The [`PrepareCallsContext`] of the prepared call bundle.
    pub context: PrepareCallsContext,
    /// Key that was used to sign the call bundle.
    pub key: CallKey,
    /// Signature value.
    pub signature: Bytes,
}

/// Response for `wallet_sendPreparedCalls`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SendPreparedCallsResponse {
    /// Bundle ID.
    pub id: BundleId,
}

/// The status code of a call bundle.
#[derive(Debug, Clone, Serialize_repr, Deserialize_repr, Eq, PartialEq)]
#[repr(u16)]
pub enum CallStatusCode {
    /// The call bundle is pending.
    Pending = 100,
    /// The call bundle was confirmed.
    Confirmed = 200,
    /// The call bundle failed offchain.
    Failed = 300,
    /// The call bundle reverted fully onchain.
    Reverted = 400,
    /// The call bundle partially reverted onchain.
    PartiallyReverted = 500,
}

impl CallStatusCode {
    /// Whether the bundle is pending.
    pub fn is_pending(&self) -> bool {
        matches!(self, CallStatusCode::Pending)
    }

    /// Whether the bundle status is final.
    pub fn is_final(&self) -> bool {
        !self.is_pending()
    }

    /// Whether the bundle was confirmed.
    pub fn is_confirmed(&self) -> bool {
        matches!(self, CallStatusCode::Confirmed)
    }

    /// Whether the bundle failed offchain.
    pub fn is_failed(&self) -> bool {
        matches!(self, CallStatusCode::Failed)
    }
}

/// A receipt for a call bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallReceipt {
    /// The chain ID the transaction was included in.
    pub chain_id: ChainId,
    /// The logs generated in the transaction.
    pub logs: Vec<Log>,
    /// The status of the transaction.
    #[serde(flatten)]
    pub status: Eip658Value,
    /// The block hash the transaction was included in.
    pub block_hash: Option<BlockHash>,
    /// The block number the transaction was included in.
    pub block_number: Option<BlockNumber>,
    /// The gas used by the transaction.
    pub gas_used: u64,
    /// The transaction hash.
    pub transaction_hash: TxHash,
}

impl CallReceipt {
    /// Attempts to decode the logs to the provided log type.
    ///
    /// Returns the first log that decodes successfully.
    ///
    /// Returns None, if none of the logs could be decoded to the provided log type or if there
    /// are no logs.
    pub fn decoded_log<E: SolEvent>(&self) -> Option<alloy::primitives::Log<E>> {
        self.logs.iter().find_map(|log| E::decode_log(&log.inner).ok())
    }
}

/// The status of a call bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallsStatus {
    /// The ID of the call bundle.
    pub id: BundleId,
    /// The status of the call bundle.
    pub status: CallStatusCode,
    /// The receipts for the call bundle.
    pub receipts: Vec<CallReceipt>,
}
