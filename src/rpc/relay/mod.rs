//! The `relay_` namespace.
//! # Ithaca Relay RPC
//!
//! Implementations of a custom `relay_` namespace.
//!
//! - `relay_estimateFee` for estimating [`Intent`] fees.
//! - `relay_sendAction` that can perform service-sponsored [EIP-7702][eip-7702] delegations and
//!   send other service-sponsored Intent's on behalf of EOAs with delegated code.
//!
//! [eip-7702]: https://eips.ethereum.org/EIPS/eip-7702

mod api;
pub use api::*;
mod fee;
mod manager;

use crate::{
    asset::AssetInfoServiceHandle,
    chains::{Chain, Chains},
    config::QuoteConfig,
    error::{AuthError, IntentError, KeysError, QuoteError, RelayError},
    price::PriceOracle,
    rpc::relay::{fee::FeeEstimator, manager::Manager},
    signers::{DynSigner, Eip712PayLoadSigner},
    storage::{RelayStorage, StorageApi},
    transactions::{InteropBundle, RelayTransaction},
    types::{
        Account, Asset, AssetDiffs, Call, CreatableAccount, FeeTokens, IntentKind, Intents, Key,
        KeyHash, KeyType, KeyWith712Signer, PartialAction, PartialIntent, Quote, Quotes, Signature,
        SignedCall, SignedCalls, SignedQuotes, VersionedContracts,
        rpc::{
            AddressOrNative, AuthorizeKey, AuthorizeKeyResponse, BundleId, CallKey,
            GetAssetsParameters, GetKeysParameters, PrepareCallsContext, PrepareCallsParameters,
            PrepareCallsResponse, PrepareCallsResponseCapabilities, SendPreparedCallsCapabilities,
        },
    },
};
use alloy::{
    primitives::{Address, B256, Bytes, ChainId, U256},
    providers::Provider,
    sol_types::SolValue,
};
use futures_util::{future::try_join_all, join};
use jsonrpsee::core::RpcResult;
use opentelemetry::trace::SpanKind;
use std::{iter, sync::Arc, time::SystemTime};
use tracing::{Instrument, Level, error, instrument, span};

/// Implementation of the Ithaca `relay_` namespace.
#[derive(Debug, Clone)]
pub struct Relay {
    inner: Arc<RelayInner>,
}

impl Manager for Relay {
    fn chains(&self) -> &Chains {
        &self.inner.chains
    }

    fn contracts(&self) -> &VersionedContracts {
        &self.inner.contracts
    }

    fn fee_recipient(&self) -> Address {
        self.inner.fee_recipient
    }

    fn priority_fee_percentile(&self) -> f64 {
        self.inner.priority_fee_percentile
    }

    fn quote_config(&self) -> &QuoteConfig {
        &self.inner.quote_config
    }

    fn fee_tokens(&self) -> &FeeTokens {
        &self.inner.fee_tokens
    }

    fn price_oracle(&self) -> &PriceOracle {
        &self.inner.price_oracle
    }

    fn asset_info(&self) -> &AssetInfoServiceHandle {
        &self.inner.asset_info
    }

    fn storage(&self) -> &dyn StorageApi {
        &self.inner.storage
    }
}

impl FeeEstimator for Relay {}

impl Relay {
    /// Create a new Ithaca relay module.
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        contracts: VersionedContracts,
        chains: Chains,
        quote_signer: DynSigner,
        funder_signer: DynSigner,
        quote_config: QuoteConfig,
        price_oracle: PriceOracle,
        fee_tokens: FeeTokens,
        fee_recipient: Address,
        storage: RelayStorage,
        asset_info: AssetInfoServiceHandle,
        priority_fee_percentile: f64,
    ) -> Self {
        let inner = RelayInner {
            contracts,
            chains,
            fee_tokens,
            fee_recipient,
            quote_signer,
            funder_signer,
            quote_config,
            price_oracle,
            storage,
            asset_info,
            priority_fee_percentile,
        };
        Self { inner: Arc::new(inner) }
    }

    #[instrument(skip_all)]
    async fn send_intents(
        &self,
        quotes: SignedQuotes,
        capabilities: SendPreparedCallsCapabilities,
        signature: Bytes,
        key: CallKey,
    ) -> RpcResult<BundleId> {
        // if we do **not** get an error here, then the quote ttl must be in the past, which means
        // it is expired
        if SystemTime::now().duration_since(quotes.ty().ttl).is_ok() {
            return Err(QuoteError::QuoteExpired.into());
        }

        // this can be done by just verifying the signature & intent hash against the rfq
        // ticket from `relay_estimateFee`'
        if !quotes
            .recover_address()
            .is_ok_and(|address| address == self.inner.quote_signer.address())
        {
            return Err(QuoteError::InvalidQuoteSignature.into());
        }

        let bundle_id = BundleId(*quotes.hash());

        // compute real signature
        let key_hash = key.key_hash();
        let signature = Signature {
            innerSignature: signature.clone(),
            keyHash: key_hash,
            prehash: key.prehash,
        }
        .abi_encode_packed()
        .into();

        // single chain workflow
        if quotes.ty().multi_chain_root.is_none() {
            self.send_single_chain_intent(&quotes, capabilities, signature, bundle_id).await
        } else {
            self.send_multichain_intents(quotes, capabilities, signature, bundle_id).await
        }
    }

    #[instrument(skip_all)]
    async fn prepare_tx(
        &self,
        bundle_id: BundleId,
        mut quote: Quote,
        capabilities: SendPreparedCallsCapabilities,
        signature: Bytes,
    ) -> RpcResult<RelayTransaction> {
        let chain_id = quote.chain_id;
        // todo: chain support should probably be checked before we send txs
        let Chain { provider, .. } =
            self.inner.chains.get(chain_id).ok_or(RelayError::UnsupportedChain(chain_id))?;

        let authorization_address = quote.authorization_address;
        let intent = &mut quote.output;

        // Fill Intent with the fee payment signature (if exists).
        intent.paymentSignature = capabilities.fee_signature.clone();

        // Fill Intent with the user signature.
        intent.signature = signature;

        // Sign fund transfers if any
        if !intent.encodedFundTransfers.is_empty() {
            // Set funder contract address and sign
            let (digest, _) = intent
                .compute_eip712_data(self.orchestrator(), &provider)
                .await
                .map_err(RelayError::from)?;
            intent.funderSignature = self
                .inner
                .funder_signer
                .sign_payload_hash(digest)
                .await
                .map_err(RelayError::from)?;
            intent.funder = self.inner.contracts.funder.address;
        }

        // Set non-eip712 payment fields. Since they are not included into the signature so we
        // need to enforce it here.
        intent.set_legacy_payment_amount(intent.prePaymentMaxAmount);

        // If there's an authorization address in the quote, we need to fetch the signed one
        // from storage.
        // todo: we should probably fetch this before sending any tx
        let authorization = if authorization_address.is_some() {
            self.inner
                .storage
                .read_account(&intent.eoa)
                .await
                .map(|opt| opt.map(|acc| acc.signed_authorization))?
        } else {
            None
        };

        // check that the authorization item matches what's in the quote
        if quote.authorization_address != authorization.as_ref().map(|auth| auth.address) {
            return Err(AuthError::InvalidAuthItem {
                expected: quote.authorization_address,
                got: authorization.map(|auth| auth.address),
            }
            .into());
        }

        if let Some(auth) = &authorization {
            // todo: same as above
            if !auth.inner().chain_id().is_zero() {
                return Err(AuthError::AuthItemNotChainAgnostic.into());
            }

            let expected_nonce =
                provider.get_transaction_count(quote.output.eoa).await.map_err(RelayError::from)?;

            if expected_nonce != auth.nonce {
                return Err(AuthError::AuthItemInvalidNonce {
                    expected: expected_nonce,
                    got: auth.nonce,
                }
                .into());
            }
        } else {
            let account = Account::new(quote.output.eoa, provider);
            // todo: same as above
            if !account.is_delegated().await? {
                return Err(AuthError::EoaNotDelegated(quote.output.eoa).into());
            }
        }

        // set our payment recipient
        quote.output.paymentRecipient = self.inner.fee_recipient;

        let tx = RelayTransaction::new(quote.clone(), authorization.clone());
        self.inner.storage.add_bundle_tx(bundle_id, chain_id, tx.id).await?;

        Ok(tx)
    }

    /// Get keys from an account.
    #[instrument(skip_all)]
    async fn get_keys(
        &self,
        request: GetKeysParameters,
    ) -> Result<Vec<AuthorizeKeyResponse>, RelayError> {
        match self.get_keys_onchain(request.clone()).await {
            Ok(keys) => Ok(keys),
            Err(err) => {
                // We check our storage, since it might have been called after createAccount, but
                // before its onchain commit.
                if let RelayError::Auth(auth_err) = &err {
                    if auth_err.is_eoa_not_delegated() {
                        if let Some(account) =
                            self.inner.storage.read_account(&request.address).await?
                        {
                            return account.authorized_keys();
                        }
                    }
                }
                Err(err)
            }
        }
    }

    /// Get keys from an account onchain.
    #[instrument(skip_all)]
    async fn get_keys_onchain(
        &self,
        request: GetKeysParameters,
    ) -> Result<Vec<AuthorizeKeyResponse>, RelayError> {
        let account = Account::new(request.address, self.provider(request.chain_id)?);

        let (is_delegated, keys) = join!(account.is_delegated(), account.keys());

        if !is_delegated? {
            return Err(AuthError::EoaNotDelegated(request.address).boxed().into());
        }

        // Get all keys from account
        let keys = keys.map_err(RelayError::from)?;

        // Get all permissions from non admin keys
        let mut permissioned_keys = account
            .permissions(keys.iter().filter(|(_, key)| !key.isSuperAdmin).map(|(hash, _)| *hash))
            .await
            .map_err(RelayError::from)?;

        Ok(keys
            .into_iter()
            .map(|(hash, key)| AuthorizeKeyResponse {
                hash,
                authorize_key: AuthorizeKey {
                    key,
                    permissions: permissioned_keys.remove(&hash).unwrap_or_default(),
                },
            })
            .collect())
    }

    /// Converts authorized keys into a list of [`Call`].
    fn authorize_into_calls(&self, keys: Vec<AuthorizeKey>) -> Result<Vec<Call>, KeysError> {
        let mut calls = Vec::with_capacity(keys.len());
        for key in keys {
            // additional_calls: permission & account registry
            let (authorize_call, additional_calls) = key.into_calls()?;
            calls.push(authorize_call);
            calls.extend(additional_calls);
        }
        Ok(calls)
    }

    /// Given a key hash and a list of [`PreCall`], it tries to find a key from a requested EOA.
    ///
    /// If it cannot find it, it will attempt to fetch it from storage or on-chain.
    async fn try_find_key(
        &self,
        from: Address,
        key_hash: KeyHash,
        pre_calls: &[SignedCall],
        chain_id: ChainId,
    ) -> Result<Option<Key>, RelayError> {
        for pre_call in pre_calls {
            if let Some(key) =
                pre_call.authorized_keys()?.iter().find(|key| key.key_hash() == key_hash)
            {
                return Ok(Some(key.clone()));
            }
        }

        Ok(self
            .get_keys(GetKeysParameters { address: from, chain_id })
            .await?
            .into_iter()
            .find(|key| key.hash == key_hash)
            .map(|k| k.authorize_key.key))
    }

    /// Generates all calls from a [`PrepareCallsParameters`].
    async fn generate_calls(
        &self,
        request: &PrepareCallsParameters,
    ) -> Result<Vec<Call>, RelayError> {
        // Generate all calls that will authorize  keys and set their permissions
        let authorize_calls =
            self.authorize_into_calls(request.capabilities.authorize_keys.clone())?;

        // Generate all revoke key calls
        let revoke_calls =
            request.capabilities.revoke_keys.iter().flat_map(|key| key.clone().into_calls());

        // Merges all previously generated calls.
        Ok(authorize_calls.into_iter().chain(request.calls.clone()).chain(revoke_calls).collect())
    }

    /// Simulates the account initialization call.
    async fn simulate_init(
        &self,
        account: &CreatableAccount,
        chain_id: ChainId,
    ) -> Result<(), RelayError> {
        let mock_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)
            .map_err(RelayError::from)
            .and_then(|k| k.ok_or_else(|| RelayError::Keys(KeysError::UnsupportedKeyType)))?;

        // Ensures that initialization precall works
        self.estimate_fee(
            PartialAction {
                intent: PartialIntent {
                    eoa: account.address,
                    execution_data: Vec::<Call>::new().abi_encode().into(),
                    nonce: U256::from_be_bytes(B256::random().into()) << 64,
                    payer: None,
                    pre_calls: vec![account.pre_call.clone()],
                    fund_transfers: vec![],
                },
                chain_id,
                prehash: false,
            },
            Address::ZERO,
            Some(account.signed_authorization.address),
            mock_key.key().clone(),
            true,
            IntentKind::Single,
        )
        .await?;

        Ok(())
    }

    /// Builds a chain intent.
    async fn build_intent(
        &self,
        request: &PrepareCallsParameters,
        maybe_stored: Option<CreatableAccount>,
        calls: Vec<Call>,
        nonce: U256,
        intent_kind: IntentKind,
    ) -> Result<(AssetDiffs, Quote), RelayError> {
        let Some(eoa) = request.from else { return Err(IntentError::MissingSender.into()) };
        let Some(request_key) = &request.key else {
            return Err(IntentError::MissingKey.into());
        };

        let key_hash = request_key.key_hash();

        // Find the key that authorizes this intent
        let Some(key) = self
            .try_find_key(eoa, key_hash, &request.capabilities.pre_calls, request.chain_id)
            .await?
        else {
            return Err(KeysError::UnknownKeyHash(key_hash).into());
        };

        // Call estimateFee to give us a quote with a complete intent that the user can sign
        let (asset_diff, quote) = self
            .estimate_fee(
                PartialAction {
                    intent: PartialIntent {
                        eoa,
                        execution_data: calls.abi_encode().into(),
                        nonce,
                        payer: request.capabilities.meta.fee_payer,
                        // stored PreCall should come first since it's been signed by the root
                        // EOA key.
                        pre_calls: maybe_stored
                            .iter()
                            .map(|acc| acc.pre_call.clone())
                            .chain(request.capabilities.pre_calls.clone())
                            .collect(),
                        fund_transfers: intent_kind.fund_transfers(),
                    },
                    chain_id: request.chain_id,
                    prehash: request_key.prehash,
                },
                request.capabilities.meta.fee_token,
                maybe_stored.as_ref().map(|acc| acc.signed_authorization.address),
                key,
                false,
                intent_kind,
            )
            .await
            .inspect_err(|err| {
                error!(
                    %err,
                    "Failed to create a quote.",
                );
            })?;

        Ok((asset_diff, quote))
    }

    async fn prepare_calls_inner(
        &self,
        request: PrepareCallsParameters,
        intent_kind: Option<IntentKind>,
    ) -> RpcResult<PrepareCallsResponse> {
        // Checks calls and precall calls in the request
        request.check_calls(self.delegation_implementation())?;

        let provider = self.provider(request.chain_id)?;

        // Find if the address is delegated or if we have a stored account in storage that can use
        // to delegate.
        let mut maybe_stored = None;
        if let Some(from) = &request.from {
            if !Account::new(*from, provider.clone()).is_delegated().await? {
                maybe_stored = Some(
                    self.inner
                        .storage
                        .read_account(from)
                        .await
                        .map_err(|e| RelayError::InternalError(e.into()))?
                        .ok_or_else(|| {
                            RelayError::Auth(AuthError::EoaNotDelegated(*from).boxed())
                        })?,
                );
            }
        }

        // Generate all requested calls.
        let calls = self.generate_calls(&request).await?;

        // Get next available nonce for DEFAULT_SEQUENCE_KEY
        let nonce = request.get_nonce(maybe_stored.as_ref(), &provider).await?;

        // If we're dealing with a PreCall do not estimate
        let (asset_diff, context) = if request.capabilities.pre_call {
            let precall = SignedCall {
                eoa: request.from.unwrap_or_default(),
                executionData: calls.abi_encode().into(),
                nonce,
                signature: Bytes::new(),
            };

            (AssetDiffs(vec![]), PrepareCallsContext::with_precall(precall))
        } else {
            let (asset_diffs, quotes) =
                self.build_quotes(&request, calls, nonce, maybe_stored, intent_kind).await?;

            let sig = self
                .inner
                .quote_signer
                .sign_hash(&quotes.digest())
                .await
                .map_err(|err| RelayError::InternalError(err.into()))?;

            (asset_diffs, PrepareCallsContext::with_quotes(quotes.into_signed(sig)))
        };

        // Calculate the digest that the user will need to sign.
        let (digest, typed_data) = context
            .compute_signing_digest(self.orchestrator(), &provider)
            .await
            .map_err(RelayError::from)?;

        let response = PrepareCallsResponse {
            context,
            digest,
            typed_data,
            capabilities: PrepareCallsResponseCapabilities {
                authorize_keys: request
                    .capabilities
                    .authorize_keys
                    .into_iter()
                    .map(|key| key.into_response())
                    .collect::<Vec<_>>(),
                revoke_keys: request.capabilities.revoke_keys,
                asset_diff,
            },
            key: request.key,
        };

        Ok(response)
    }

    /// Build quote with optional funding chain detection
    async fn build_quotes(
        &self,
        request: &PrepareCallsParameters,
        calls: Vec<Call>,
        nonce: U256,
        maybe_stored: Option<CreatableAccount>,
        intent_kind: Option<IntentKind>,
    ) -> RpcResult<(AssetDiffs, Quotes)> {
        // Check if funding is required
        if let Some((requested_asset, funds)) = request.required_funds.first() {
            self.determine_quote_strategy(
                request,
                *requested_asset,
                *funds,
                calls,
                nonce,
                maybe_stored,
            )
            .await
        } else {
            self.build_single_chain_quote(request, maybe_stored, calls, nonce, intent_kind)
                .await
                .map_err(Into::into)
        }
    }

    /// Determine quote strategy based on asset availability across chains
    async fn determine_quote_strategy(
        &self,
        request: &PrepareCallsParameters,
        requested_asset: Address,
        funds: U256,
        calls: Vec<Call>,
        nonce: U256,
        maybe_stored: Option<CreatableAccount>,
    ) -> RpcResult<(AssetDiffs, Quotes)> {
        let eoa = request.from.ok_or(IntentError::MissingSender)?;
        // Only query inventory, if funds have been requested in the target chain.
        let asset = if requested_asset.is_zero() {
            AddressOrNative::Native
        } else {
            AddressOrNative::Address(requested_asset)
        };

        // todo: what about fees?
        let assets_response = self.get_assets(GetAssetsParameters::eoa(eoa)).await?;

        let Some(funding_chains) =
            assets_response.find_funding_chains(request.chain_id, asset, funds)
        else {
            return Err(RelayError::InsufficientFunds {
                required: funds,
                chain_id: request.chain_id,
                asset: requested_asset,
            }
            .into());
        };

        if funding_chains.is_empty() {
            // No funding chains required to execute the intent
            self.build_single_chain_quote(
                request,
                maybe_stored,
                calls,
                nonce,
                Some(IntentKind::Single),
            )
            .await
            .map_err(Into::into)
        } else {
            Ok(self
                .build_multichain_quote(request, funding_chains, calls, nonce, maybe_stored)
                .await?)
        }
    }

    /// Build a single-chain quote
    async fn build_single_chain_quote(
        &self,
        request: &PrepareCallsParameters,
        maybe_stored: Option<CreatableAccount>,
        calls: Vec<Call>,
        nonce: U256,
        intent_kind: Option<IntentKind>,
    ) -> Result<(AssetDiffs, Quotes), RelayError> {
        let (asset_diffs, quote) = self
            .build_intent(
                request,
                maybe_stored,
                calls,
                nonce,
                intent_kind.unwrap_or(IntentKind::Single),
            )
            .await?;

        Ok((
            asset_diffs,
            Quotes {
                quotes: vec![quote],
                ttl: SystemTime::now()
                    .checked_add(self.inner.quote_config.ttl)
                    .expect("should never overflow"),
                multi_chain_root: None,
            },
        ))
    }

    /// Build a multi-chain quote with funding from funding chains.
    ///
    /// 1) Create funding intents for each chain to bridge assets.
    /// 2) Create output intent for destination chain
    /// 3) Creates the multi chain intent merkle tree
    /// 4) Return overall quote.
    async fn build_multichain_quote(
        &self,
        request: &PrepareCallsParameters,
        funding_chains: Vec<(u64, U256)>,
        calls: Vec<Call>,
        nonce: U256,
        maybe_stored: Option<CreatableAccount>,
    ) -> RpcResult<(AssetDiffs, Quotes)> {
        let eoa = request.from.ok_or(IntentError::MissingSender)?;
        let request_key = request.key.as_ref().ok_or(IntentError::MissingKey)?;
        let requested_asset = request
            .required_funds
            .first()
            .map(|(asset, _)| *asset)
            .ok_or_else(|| RelayError::Quote(QuoteError::MissingRequiredFunds))?;

        let asset: Asset = if requested_asset.is_zero() {
            AddressOrNative::Native
        } else {
            AddressOrNative::Address(requested_asset)
        }
        .into();

        let funding_intents = try_join_all(funding_chains.iter().enumerate().map(
            async |(leaf, (chain_id, amount))| {
                self.prepare_calls_inner(
                    PrepareCallsParameters::build_funding_intent(
                        eoa,
                        *chain_id,
                        asset,
                        *amount,
                        // todo: should get the equivalent coin
                        request.capabilities.meta.fee_token,
                        request_key.clone(),
                    ),
                    Some(IntentKind::MultiInput(leaf)),
                )
                .await
            },
        ))
        .await?;

        let mut sourced_funds = U256::ZERO;
        for (_, amount) in funding_chains.iter() {
            sourced_funds += amount;
        }

        let (asset_diffs, quote) = self
            .build_intent(
                request,
                maybe_stored,
                calls,
                nonce,
                IntentKind::MultiOutput(
                    funding_intents.len(),
                    vec![(requested_asset, sourced_funds)],
                ),
            )
            .await?;

        // todo: assetdiffs should change
        Ok((
            asset_diffs,
            Quotes {
                quotes: funding_intents
                    .iter()
                    .flat_map(|resp| {
                        resp.context.quote().expect("should exist").ty().quotes.clone()
                    })
                    .chain(std::iter::once(quote))
                    .collect(),
                ttl: SystemTime::now()
                    .checked_add(self.inner.quote_config.ttl)
                    .expect("should never overflow"),
                multi_chain_root: None,
            }
            .with_merkle_payload(
                funding_chains
                    .iter()
                    .chain(iter::once(&(request.chain_id, U256::ZERO)))
                    .map(|(chain, _)| {
                        self.provider(*chain)
                            .map(|p| (p, self.inner.contracts.orchestrator.address))
                    })
                    .collect::<Result<Vec<_>, _>>()?,
            )
            .await?,
        ))
    }

    /// Handle single-chain send intent
    async fn send_single_chain_intent(
        &self,
        quotes: &SignedQuotes,
        capabilities: SendPreparedCallsCapabilities,
        signature: Bytes,
        bundle_id: BundleId,
    ) -> RpcResult<BundleId> {
        // send intent
        let tx = self
            .prepare_tx(
                bundle_id,
                // safety: we know there is 1 element
                quotes.ty().quotes.first().unwrap().clone(),
                capabilities,
                signature,
            )
            .await?;

        let span = span!(
            Level::INFO, "send tx",
            otel.kind = ?SpanKind::Producer,
            messaging.system = "pg",
            messaging.destination.name = "tx",
            messaging.operation.name = "send",
            messaging.operation.type = "send",
            messaging.message.id = %tx.id
        );
        self.inner
            .chains
            .get(tx.chain_id())
            .ok_or_else(|| RelayError::UnsupportedChain(tx.chain_id()))?
            .transactions
            .send_transaction(tx)
            .instrument(span)
            .await?;

        Ok(bundle_id)
    }

    /// Handle multichain send intents
    async fn send_multichain_intents(
        &self,
        mut quotes: SignedQuotes,
        capabilities: SendPreparedCallsCapabilities,
        signature: Bytes,
        bundle_id: BundleId,
    ) -> RpcResult<BundleId> {
        let bundle =
            self.create_interop_bundle(bundle_id, &mut quotes, &capabilities, &signature).await?;

        self.inner.chains.interop().send_bundle(bundle).map_err(RelayError::internal)?;

        Ok(bundle_id)
    }

    /// Creates an InteropBundle from signed quotes for multichain transactions.
    async fn create_interop_bundle(
        &self,
        bundle_id: BundleId,
        quotes: &mut SignedQuotes,
        capabilities: &SendPreparedCallsCapabilities,
        signature: &Bytes,
    ) -> Result<InteropBundle, RelayError> {
        let mut intents = Intents::new(
            quotes
                .ty()
                .quotes
                .iter()
                .map(|quote| {
                    (
                        quote.output.clone(),
                        self.provider(quote.chain_id).unwrap(),
                        quote.orchestrator,
                    )
                })
                .collect(),
        );

        let mut bundle = InteropBundle {
            id: bundle_id,
            src_transactions: Vec::new(),
            dst_transactions: Vec::new(),
        };

        // last quote is the output intent
        let dst_idx = quotes.ty().quotes.len() - 1;

        // todo: error handling
        let root = intents.root().await.unwrap();
        for (idx, quote) in quotes.ty_mut().quotes.iter_mut().enumerate() {
            let proof = intents.get_proof(idx).await.unwrap().unwrap();
            let merkle_sig = (proof, root, signature.clone()).abi_encode_params();
            let tx = self
                .prepare_tx(bundle_id, quote.clone(), capabilities.clone(), merkle_sig.into())
                .await
                .map_err(|e| RelayError::InternalError(e.into()))?;

            if idx == dst_idx {
                bundle.dst_transactions.push(tx.clone());
            } else {
                bundle.src_transactions.push(tx.clone());
            }
        }

        Ok(bundle)
    }
}

/// Implementation of the Ithaca `relay_` namespace.
#[derive(Debug)]
pub(super) struct RelayInner {
    /// The contract addresses.
    contracts: VersionedContracts,
    /// The chains supported by the relay.
    chains: Chains,
    /// Supported fee tokens.
    fee_tokens: FeeTokens,
    /// The fee recipient address.
    fee_recipient: Address,
    /// The signer used to sign quotes.
    quote_signer: DynSigner,
    /// The signer used to sign fund transfers.
    funder_signer: DynSigner,
    /// Quote related configuration.
    quote_config: QuoteConfig,
    /// Price oracle.
    price_oracle: PriceOracle,
    /// Storage
    storage: RelayStorage,
    /// AssetInfo
    asset_info: AssetInfoServiceHandle,
    /// Percentile of the priority fees to use for the transactions.
    priority_fee_percentile: f64,
}
