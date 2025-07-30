//! RPC calls-related request and response types.

use std::collections::HashMap;

use super::{AuthorizeKey, AuthorizeKeyResponse, Meta, RevokeKey};
use crate::{
    error::{IntentError, RelayError},
    storage::BundleStatus,
    types::{
        Account, AssetDiffResponse, AssetType, Call, CreatableAccount, DEFAULT_SEQUENCE_KEY, Key,
        KeyType, MULTICHAIN_NONCE_PREFIX_U192, SignedCall, SignedCalls, SignedQuotes,
    },
};
use alloy::{
    consensus::Eip658Value,
    contract::StorageSlotFinder,
    dyn_abi::TypedData,
    primitives::{
        Address, B256, BlockHash, BlockNumber, Bytes, ChainId, TxHash, U256,
        aliases::{B192, U192},
        map::B256HashMap,
        wrap_fixed_bytes,
    },
    providers::{DynProvider, Provider},
    rpc::types::{
        Log,
        state::{AccountOverride, StateOverride, StateOverridesBuilder},
    },
    sol_types::SolEvent,
    uint,
};
use futures_util::future::try_join_all;
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

/// A set of balance overrides.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BalanceOverrides {
    balances: HashMap<Address, BalanceOverride>,
}

impl BalanceOverrides {
    /// Create a new balance override.
    pub fn new(balances: HashMap<Address, BalanceOverride>) -> Self {
        Self { balances }
    }

    /// Modifies the balance override for a token.
    ///
    /// If there is not an existing balance override, a new one will be created with
    /// [`AssetType::ERC20`].
    ///
    /// # Example
    ///
    /// ```rust
    /// # let account = Address::ZERO;
    /// BalanceOverrides::default().modify_token(Address::ZERO, |bal| {
    ///     bal.add_balance(account, U256::from(2));
    /// })
    /// ```
    pub fn modify_token<F>(mut self, token: Address, f: F) -> Self
    where
        F: FnOnce(&mut BalanceOverride),
    {
        f(self.balances.entry(token).or_insert_with(|| BalanceOverride::new(AssetType::ERC20)));
        self
    }

    /// Convert the balance overrides into state overrides.
    ///
    /// # Note
    ///
    /// This finds storage slots for the assets and might be slow since it fetches access lists for
    /// each balance override.
    pub async fn into_state_overrides<P: Provider + Clone>(
        self,
        provider: P,
    ) -> Result<StateOverride, RelayError> {
        async fn account_override_for_token<P: Provider + Clone>(
            provider: P,
            token_address: Address,
            balances: HashMap<Address, U256>,
        ) -> Result<AccountOverride, RelayError> {
            let slots: B256HashMap<B256> =
                try_join_all(balances.into_iter().map(|(account, balance)| {
                    let provider = provider.clone();

                    async move {
                        let slot = StorageSlotFinder::balance_of(provider, token_address, account)
                            .find_slot()
                            .await?;

                        Ok::<_, RelayError>((
                            slot.ok_or_else(|| {
                                eyre::eyre!(format!(
                                    "could not determine balance slot for {}",
                                    token_address
                                ))
                            })?,
                            balance.into(),
                        ))
                    }
                }))
                .await?
                .into_iter()
                .collect();

            Ok::<_, RelayError>(AccountOverride { state_diff: Some(slots), ..Default::default() })
        }

        let account_overrides: Vec<(Address, AccountOverride)> =
            try_join_all(self.balances.into_iter().map(|(token_address, overrides)| {
                let provider = provider.clone();
                async move {
                    Ok::<_, RelayError>((
                        token_address,
                        account_override_for_token(
                            provider.clone(),
                            token_address,
                            overrides.balances,
                        )
                        .await?,
                    ))
                }
            }))
            .await?;

        Ok(StateOverridesBuilder::default().extend(account_overrides).build())
    }
}

/// A balance override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalanceOverride {
    /// The kind of asset this is.
    ///
    /// # Note
    ///
    /// Currently this only supports ERC20, so it should be validated that this is equal to ERC20.
    kind: AssetType,
    /// The balances to override.
    balances: HashMap<Address, U256>,
}

impl BalanceOverride {
    /// Create a new balance override
    pub fn new(kind: AssetType) -> Self {
        Self { kind, balances: Default::default() }
    }

    /// Adds the given balance to the given account.
    ///
    /// This operation is additive; if a balance override already exists for this account, the
    /// passed balance is added onto the current override.
    pub fn add_balance(&mut self, account: Address, balance: U256) -> &mut Self {
        let current_balance = self.balances.entry(account).or_default();
        *current_balance = current_balance.saturating_add(balance);
        self
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
    /// Balance overrides for simulating the call bundle.
    ///
    /// This will only be applied to the intent on the output chain in multichain intents.
    ///
    /// This uses heuristics to determine the balance slot, so it might be inaccurate in some
    /// cases.
    #[serde(default)]
    pub balance_overrides: BalanceOverrides,
    /// Key that will be used to sign the call bundle. It can only be None, if we are handling a
    /// precall.
    #[serde(default)]
    pub key: Option<CallKey>,
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
    /// Required funds on the target chain.
    #[serde(default)]
    pub required_funds: Vec<RequiredAsset>,
}

/// A required asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RequiredAsset {
    /// The address of the required asset.
    pub address: Address,
    /// The value required.
    pub value: U256,
}

impl RequiredAsset {
    /// Create a new [`RequiredAsset`].
    pub const fn new(address: Address, value: U256) -> Self {
        Self { address, value }
    }
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
    /// The [`AssetDiffResponse`] of the prepared call bundle, flattened.
    #[serde(flatten)]
    pub asset_diff: AssetDiffResponse,
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    /// The call bundle was preconfirmed.
    ///
    /// Note that this status is returned if all receipts are available and at least one of the
    /// receipts is for a block in the future, indicating it was preconfirmed. It does not
    /// necessarily indicate that all transactions were preconfirmed.
    PreConfirmed = 201,
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
    /// Optional capabilities for the call bundle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<CallsStatusCapabilities>,
}

/// Capabilities for call status.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CallsStatusCapabilities {
    /// Interop bundle status if this is an interop bundle.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interop_status: Option<BundleStatus>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;
    use std::str::FromStr;

    #[test]
    fn serde_balance_overrides() {
        let s = r#"{
            "balances": {
                "0x97870b32890d3F1f089489A29007863A5678089D": "0x56bc75e2d63100000"
            },
            "kind": "erc20"
        }"#;
        let params = serde_json::from_str::<BalanceOverride>(s).unwrap();
        let balance_override = BalanceOverride {
            kind: AssetType::ERC20,
            balances: HashMap::from([(
                address!("0x97870b32890d3F1f089489A29007863A5678089D"),
                U256::from_str("0x56bc75e2d63100000").unwrap(),
            )]),
        };
        assert_eq!(params, balance_override);
    }

    #[test]
    fn serde_prepare_params() {
        let s = r#"{
    "balanceOverrides": {
        "0x7ddb34adbf9a11d3fe365349c607fc7b09954a41": {
            "balances": {
                "0x97870b32890d3F1f089489A29007863A5678089D": "0x56bc75e2d63100000"
            },
            "kind": "erc20"
        }
    },
    "calls": [
        {
            "data": "0x40c10f190000000000000000000000007ddb34adbf9a11d3fe365349c607fc7b09954a410000000000000000000000000000000000000000000000000de0b6b3a7640000",
            "to": "0x97870b32890d3F1f089489A29007863A5678089D",
            "value": "0x0"
        }
    ],
    "capabilities": {
        "meta": {
            "feeToken": "0x97870b32890d3F1f089489A29007863A5678089D"
        }
    },
    "chainId": 28404,
    "from": "0x7ddb34adbf9a11d3fe365349c607fc7b09954a41",
    "key": {
        "prehash": false,
        "publicKey": "0x4bc484680a02b7edba11d82f320c968e08a896f24130eca04b8dea6538ae5d5d4de1da458be057268f4164f8a44d95afc8ec0991836c8397c5c6146fcba5fa99",
        "type": "webauthnp256"
    },
    "requiredFunds": []
}"#;
        let params = serde_json::from_str::<PrepareCallsParameters>(s).unwrap();
        let balance_override = params
            .balance_overrides
            .balances
            .get(&address!("0x7ddb34adbf9a11d3fe365349c607fc7b09954a41"))
            .unwrap();
        let expected = BalanceOverride {
            kind: AssetType::ERC20,
            balances: HashMap::from([(
                address!("0x97870b32890d3F1f089489A29007863A5678089D"),
                U256::from_str("0x56bc75e2d63100000").unwrap(),
            )]),
        };
        assert_eq!(*balance_override, expected);
    }
}
