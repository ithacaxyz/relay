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

use crate::{
    asset::AssetInfoServiceHandle,
    error::IntentError,
    provider::ProviderExt,
    types::{
        AccountRegistry::{self, AccountRegistryCalls},
        AssetDiffs, Call, FeeTokens, GasEstimate, Key, KeyHash, KeyHashWithID, KeyType,
        ORCHESTRATOR_NO_ERROR,
        OrchestratorContract::{self, IntentExecuted},
        SignedCall, SignedCalls, VersionedContracts,
        rpc::{
            CallReceipt, CallStatusCode, ChainCapabilities, ChainFees, CreateAccountContext,
            PrepareCallsContext, RelayCapabilities, ValidSignatureProof,
        },
    },
    version::RELAY_SHORT_VERSION,
};
use alloy::{
    consensus::{SignableTransaction, TxEip1559},
    eips::eip7702::{
        SignedAuthorization,
        constants::{EIP7702_DELEGATION_DESIGNATOR, PER_EMPTY_ACCOUNT_COST},
    },
    primitives::{Address, Bytes, ChainId, U256, bytes},
    providers::{
        DynProvider, Provider,
        utils::{EIP1559_FEE_ESTIMATION_PAST_BLOCKS, Eip1559Estimator},
    },
    rpc::types::{
        TransactionReceipt,
        state::{AccountOverride, StateOverridesBuilder},
    },
    sol_types::{SolCall, SolValue},
};
use futures_util::{
    TryFutureExt,
    future::{TryJoinAll, try_join_all, try_join4},
    join,
};
use jsonrpsee::{
    core::{RpcResult, async_trait},
    proc_macros::rpc,
};
use opentelemetry::trace::SpanKind;
use std::{sync::Arc, time::SystemTime};
use tokio::try_join;
use tracing::{Instrument, Level, debug, error, instrument, span};

use crate::{
    chains::{Chain, Chains},
    config::QuoteConfig,
    error::{AuthError, KeysError, QuoteError, RelayError},
    price::PriceOracle,
    signers::DynSigner,
    storage::{RelayStorage, StorageApi},
    transactions::{RelayTransaction, TransactionStatus},
    types::{
        Account, CreatableAccount, Intent, KeyWith712Signer, Orchestrator, PREPAccount,
        PartialAction, PartialIntent, Quote, Signature, SignedQuote,
        rpc::{
            AccountResponse, AuthorizeKey, AuthorizeKeyResponse, BundleId, CallsStatus,
            CreateAccountParameters, GetAccountsParameters, GetKeysParameters,
            PrepareCallsParameters, PrepareCallsResponse, PrepareCallsResponseCapabilities,
            PrepareCreateAccountParameters, PrepareCreateAccountResponse,
            PrepareUpgradeAccountParameters, SendPreparedCallsParameters,
            SendPreparedCallsResponse, UpgradeAccountParameters, UpgradeAccountResponse,
            VerifySignatureParameters, VerifySignatureResponse,
        },
    },
};

/// Ithaca `relay_` RPC namespace.
#[rpc(server, client, namespace = "relay")]
pub trait RelayApi {
    /// Checks the health of the relay and returns its version.
    #[method(name = "health", aliases = ["health"])]
    async fn health(&self) -> RpcResult<String>;

    /// Get capabilities of the relay, which are different sets of configuration values.
    #[method(name = "getCapabilities", aliases = ["wallet_getCapabilities"])]
    async fn get_capabilities(&self, chains: Vec<ChainId>) -> RpcResult<RelayCapabilities>;

    /// Prepares an account for the user.
    #[method(name = "prepareCreateAccount", aliases = ["wallet_prepareCreateAccount"])]
    async fn prepare_create_account(
        &self,
        parameters: PrepareCreateAccountParameters,
    ) -> RpcResult<PrepareCreateAccountResponse>;

    /// Initialize an account.
    #[method(name = "createAccount", aliases = ["wallet_createAccount"])]
    async fn create_account(
        &self,
        parameters: CreateAccountParameters,
    ) -> RpcResult<Vec<KeyHashWithID>>;

    /// Get all accounts from an ID.
    #[method(name = "getAccounts", aliases = ["wallet_getAccounts"])]
    async fn get_accounts(
        &self,
        parameters: GetAccountsParameters,
    ) -> RpcResult<Vec<AccountResponse>>;

    /// Get all keys for an account.
    #[method(name = "getKeys", aliases = ["wallet_getKeys"])]
    async fn get_keys(&self, parameters: GetKeysParameters)
    -> RpcResult<Vec<AuthorizeKeyResponse>>;

    /// Prepares a call bundle for a user.
    #[method(name = "prepareCalls", aliases = ["wallet_prepareCalls"])]
    async fn prepare_calls(
        &self,
        parameters: PrepareCallsParameters,
    ) -> RpcResult<PrepareCallsResponse>;

    /// Prepares an EOA to be upgraded.
    #[method(name = "prepareUpgradeAccount", aliases = ["wallet_prepareUpgradeAccount"])]
    async fn prepare_upgrade_account(
        &self,
        parameters: PrepareUpgradeAccountParameters,
    ) -> RpcResult<PrepareCallsResponse>;

    /// Send a signed call bundle.
    #[method(name = "sendPreparedCalls", aliases = ["wallet_sendPreparedCalls"])]
    async fn send_prepared_calls(
        &self,
        parameters: SendPreparedCallsParameters,
    ) -> RpcResult<SendPreparedCallsResponse>;

    /// Upgrade an account.
    #[method(name = "upgradeAccount", aliases = ["wallet_upgradeAccount"])]
    async fn upgrade_account(
        &self,
        parameters: UpgradeAccountParameters,
    ) -> RpcResult<UpgradeAccountResponse>;

    /// Get the status of a call batch that was sent via `send_prepared_calls`.
    ///
    /// The identifier of the batch is the value returned from `send_prepared_calls`.
    #[method(name = "getCallsStatus", aliases = ["wallet_getCallsStatus"])]
    async fn get_calls_status(&self, parameters: BundleId) -> RpcResult<CallsStatus>;

    /// Get the status of a call batch that was sent via `send_prepared_calls`.
    ///
    /// The identifier of the batch is the value returned from `send_prepared_calls`.
    #[method(name = "verifySignature", aliases = ["wallet_verifySignature"])]
    async fn verify_signature(
        &self,
        parameters: VerifySignatureParameters,
    ) -> RpcResult<VerifySignatureResponse>;
}

/// Implementation of the Ithaca `relay_` namespace.
#[derive(Debug)]
pub struct Relay {
    inner: Arc<RelayInner>,
}

impl Relay {
    /// Create a new Ithaca relay module.
    #[expect(clippy::too_many_arguments)]
    pub fn new(
        contracts: VersionedContracts,
        chains: Chains,
        quote_signer: DynSigner,
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
            quote_config,
            price_oracle,
            storage,
            asset_info,
            priority_fee_percentile,
        };
        Self { inner: Arc::new(inner) }
    }

    /// Estimates additional fees to be paid for a intent (e.g L1 DA fees).
    ///
    /// Returns fees in ETH.
    #[instrument(skip_all)]
    async fn estimate_extra_fee(&self, chain: &Chain, intent: &Intent) -> Result<U256, RelayError> {
        // Include the L1 DA fees if we're on an OP rollup.
        let fee = if chain.is_optimism {
            // Create a dummy transactions with all fields set to max values to make sure that
            // calldata is largest possible
            let tx = TxEip1559 {
                chain_id: chain.chain_id,
                nonce: u64::MAX,
                gas_limit: u64::MAX,
                max_fee_per_gas: u128::MAX,
                max_priority_fee_per_gas: u128::MAX,
                to: (!Address::ZERO).into(),
                input: intent.encode_execute(),
                ..Default::default()
            };
            let signature = alloy::signers::Signature::new(U256::MAX, U256::MAX, true);

            let encoded = {
                let tx = tx.into_signed(signature);
                let mut buf = Vec::with_capacity(tx.eip2718_encoded_length());
                tx.eip2718_encode(&mut buf);
                buf
            };

            chain.provider.estimate_l1_fee(encoded.into()).await?
        } else {
            U256::ZERO
        };

        Ok(fee)
    }

    #[instrument(skip_all)]
    async fn estimate_fee(
        &self,
        request: PartialAction,
        token: Address,
        authorization_address: Option<Address>,
        account_key: Key,
        key_slot_override: bool,
    ) -> Result<(AssetDiffs, SignedQuote), RelayError> {
        let chain = self
            .inner
            .chains
            .get(request.chain_id)
            .ok_or(RelayError::UnsupportedChain(request.chain_id))?;
        let provider = chain.provider.clone();
        let Some(token) = self.inner.fee_tokens.find(request.chain_id, &token) else {
            return Err(QuoteError::UnsupportedFeeToken(token).into());
        };

        // create key
        let mock_key = KeyWith712Signer::random_admin(account_key.keyType)
            .map_err(RelayError::from)
            .and_then(|k| k.ok_or_else(|| RelayError::Keys(KeysError::UnsupportedKeyType)))?;

        // mocking key storage for the eoa, and the balance for the mock signer
        let overrides = StateOverridesBuilder::with_capacity(2)
            // simulateV1Logs requires it, so the function can only be called under a testing
            // environment
            .append(self.simulator(), AccountOverride::default().with_balance(U256::MAX))
            .append(self.orchestrator(), AccountOverride::default().with_balance(U256::MAX))
            .append(
                request.intent.eoa,
                AccountOverride::default()
                    .with_balance(U256::MAX.div_ceil(2.try_into().unwrap()))
                    .with_state_diff(if key_slot_override {
                        account_key.storage_slots()
                    } else {
                        Default::default()
                    })
                    // we manually etch the 7702 designator since we do not have a signed auth item
                    .with_code_opt(authorization_address.map(|addr| {
                        Bytes::from([&EIP7702_DELEGATION_DESIGNATOR, addr.as_slice()].concat())
                    })),
            )
            .build();

        let account = Account::new(request.intent.eoa, &provider).with_overrides(overrides.clone());

        let (orchestrator, delegation, fee_history, eth_price) = try_join4(
            // fetch orchestrator from the account and ensure it is supported
            async {
                let orchestrator = account.get_orchestrator().await?;
                if !self.is_supported_orchestrator(&orchestrator) {
                    return Err(RelayError::UnsupportedOrchestrator(orchestrator));
                }
                Ok(Orchestrator::new(orchestrator, &provider).with_overrides(overrides.clone()))
            },
            // fetch delegation from the account and ensure it is supported
            self.has_supported_delegation(&account).map_err(RelayError::from),
            // fetch chain fees
            provider
                .get_fee_history(
                    EIP1559_FEE_ESTIMATION_PAST_BLOCKS,
                    Default::default(),
                    &[self.inner.priority_fee_percentile],
                )
                .map_err(RelayError::from),
            // fetch price in eth
            async {
                // TODO: only handles eth as native fee token
                Ok(self.inner.price_oracle.eth_price(token.kind).await)
            },
        )
        .await?;

        let native_fee_estimate = Eip1559Estimator::default().estimate(
            fee_history.latest_block_base_fee().unwrap_or_default(),
            &fee_history.reward.unwrap_or_default(),
        );

        let Some(eth_price) = eth_price else {
            return Err(QuoteError::UnavailablePrice(token.address).into());
        };
        let payment_per_gas = (native_fee_estimate.max_fee_per_gas as f64
            * 10u128.pow(token.decimals as u32) as f64)
            / f64::from(eth_price);

        // fill intent
        let mut intent = Intent {
            eoa: request.intent.eoa,
            executionData: request.intent.execution_data.clone(),
            nonce: request.intent.nonce,
            payer: request.intent.payer.unwrap_or_default(),
            paymentToken: token.address,
            paymentRecipient: self.inner.fee_recipient,
            initData: request.intent.init_data.unwrap_or_default(),
            supportedAccountImplementation: delegation,
            encodedPreCalls: request
                .intent
                .pre_calls
                .into_iter()
                .map(|pre_call| pre_call.abi_encode().into())
                .collect(),
            ..Default::default()
        };

        // sign intent
        let signature = mock_key
            .sign_typed_data(
                &intent.as_eip712().map_err(RelayError::from)?,
                &orchestrator
                    .eip712_domain(intent.is_multichain())
                    .await
                    .map_err(RelayError::from)?,
            )
            .await
            .map_err(RelayError::from)?;

        intent.signature = Signature {
            innerSignature: signature,
            keyHash: account_key.key_hash(),
            prehash: request.prehash,
        }
        .abi_encode_packed()
        .into();

        let extra_payment = self.estimate_extra_fee(&chain, &intent).await?
            * U256::from(10u128.pow(token.decimals as u32))
            / eth_price;

        let intrinsic_gas = approx_intrinsic_cost(
            &OrchestratorContract::executeCall { encodedIntent: intent.abi_encode().into() }
                .abi_encode(),
            authorization_address.is_some(),
        );

        let initial_payment = U256::from(intrinsic_gas as f64 * payment_per_gas) + extra_payment;

        intent.set_legacy_payment_amount(initial_payment);

        // we estimate gas and fees
        let (asset_diff, sim_result) = orchestrator
            .simulate_execute(
                self.simulator(),
                &intent,
                account_key.keyType,
                payment_per_gas,
                self.inner.asset_info.clone(),
            )
            .await?;

        // todo: re-evaluate if this is still necessary
        let gas_estimate = GasEstimate::from_combined_gas(
            sim_result.gCombined.to(),
            intrinsic_gas,
            &self.inner.quote_config,
        );

        debug!(eoa = %request.intent.eoa, gas_estimate = ?gas_estimate, "Estimated intent");

        // Fill combinedGas and empty dummy signature
        intent.combinedGas = U256::from(gas_estimate.intent);
        intent.signature = bytes!("");

        // Calculate amount with updated paymentPerGas
        intent.set_legacy_payment_amount(
            extra_payment + U256::from((payment_per_gas * gas_estimate.tx as f64).ceil()),
        );

        let quote = Quote {
            chain_id: request.chain_id,
            payment_token_decimals: token.decimals,
            intent,
            extra_payment,
            eth_price,
            tx_gas: gas_estimate.tx,
            native_fee_estimate,
            ttl: SystemTime::now()
                .checked_add(self.inner.quote_config.ttl)
                .expect("should never overflow"),
            authorization_address,
            orchestrator: *orchestrator.address(),
        };
        let sig = self
            .inner
            .quote_signer
            .sign_hash(&quote.digest())
            .await
            .map_err(|err| RelayError::InternalError(err.into()))?;

        Ok((asset_diff, quote.into_signed(sig)))
    }

    #[instrument(skip_all)]
    async fn send_action(
        &self,
        mut quote: SignedQuote,
        authorization: Option<SignedAuthorization>,
    ) -> RpcResult<BundleId> {
        let chain_id = quote.ty().chain_id;
        let Chain { provider, transactions, .. } =
            self.inner.chains.get(chain_id).ok_or(RelayError::UnsupportedChain(chain_id))?;

        // check that the authorization item matches what's in the quote
        if quote.ty().authorization_address != authorization.as_ref().map(|auth| auth.address) {
            return Err(AuthError::InvalidAuthItem {
                expected: quote.ty().authorization_address,
                got: authorization.map(|auth| auth.address),
            }
            .into());
        }

        if let Some(auth) = &authorization {
            if !auth.inner().chain_id().is_zero() {
                return Err(AuthError::AuthItemNotChainAgnostic.into());
            }

            let expected_nonce = provider
                .get_transaction_count(quote.ty().intent.eoa)
                .await
                .map_err(RelayError::from)?;

            if expected_nonce != auth.nonce {
                return Err(AuthError::AuthItemInvalidNonce {
                    expected: expected_nonce,
                    got: auth.nonce,
                }
                .into());
            }
        } else {
            let account = Account::new(quote.ty().intent.eoa, provider);
            if !account.is_delegated().await? {
                return Err(AuthError::EoaNotDelegated(quote.ty().intent.eoa).into());
            }
        }

        // this can be done by just verifying the signature & intent hash against the rfq
        // ticket from `relay_estimateFee`'
        if !quote
            .recover_address()
            .is_ok_and(|address| address == self.inner.quote_signer.address())
        {
            return Err(QuoteError::InvalidQuoteSignature.into());
        }

        // if we do **not** get an error here, then the quote ttl must be in the past, which means
        // it is expired
        if SystemTime::now().duration_since(quote.ty().ttl).is_ok() {
            return Err(QuoteError::QuoteExpired.into());
        }

        // set our payment recipient
        quote.ty_mut().intent.paymentRecipient = self.inner.fee_recipient;

        let tx = RelayTransaction::new(quote, authorization);

        // TODO: Right now we only support a single transaction per action and per bundle, so we can
        // simply set BundleId to TxId. Eventually bundles might contain multiple transactions and
        // this is already supported by current storage API.
        let bundle_id = BundleId(*tx.id);
        self.inner.storage.add_bundle_tx(bundle_id, chain_id, tx.id).await?;

        let span = span!(
            Level::INFO, "send tx",
            otel.kind = ?SpanKind::Producer,
            messaging.system = "pg",
            messaging.destination.name = "tx",
            messaging.operation.name = "send",
            messaging.operation.type = "send",
            messaging.message.id = %tx.id
        );
        transactions.send_transaction(tx).instrument(span).await?;

        Ok(bundle_id)
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
                            self.inner.storage.read_prep(&request.address).await?
                        {
                            return Ok(account.prep.authorized_keys());
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
                    signature: None,
                },
            })
            .collect())
    }

    /// Returns the delegation implementation address from the requested account.
    ///
    /// It will return error if the delegation proxy is invalid.
    #[instrument(skip_all)]
    async fn get_delegation_implementation<P: Provider + Clone>(
        &self,
        account: &Account<P>,
    ) -> Result<Address, RelayError> {
        if let Some(delegation) = account.delegation_implementation().await? {
            return Ok(delegation);
        }

        // Attempt to retrieve the delegation proxy from storage, since it might not be
        // deployed yet.
        let Some(prep) = self.inner.storage.read_prep(&account.address()).await? else {
            return Err(RelayError::Auth(AuthError::EoaNotDelegated(account.address()).boxed()));
        };

        let address = account.address();
        let account = account.clone().with_overrides(
            StateOverridesBuilder::default()
                .with_code(
                    address,
                    Bytes::from(
                        [
                            &EIP7702_DELEGATION_DESIGNATOR,
                            prep.prep.signed_authorization.address().as_slice(),
                        ]
                        .concat(),
                    ),
                )
                .build(),
        );

        account.delegation_implementation().await?.ok_or_else(|| {
            RelayError::Auth(
                AuthError::InvalidDelegationProxy(*prep.prep.signed_authorization.address())
                    .boxed(),
            )
        })
    }

    /// Returns the chain [`DynProvider`].
    pub fn provider(&self, chain_id: ChainId) -> Result<DynProvider, RelayError> {
        Ok(self.inner.chains.get(chain_id).ok_or(RelayError::UnsupportedChain(chain_id))?.provider)
    }

    /// Converts authorized keys into a list of [`Call`].
    fn authorize_into_calls(
        &self,
        keys: Vec<AuthorizeKey>,
        account: Option<Address>,
    ) -> Result<Vec<Call>, KeysError> {
        let mut calls = Vec::with_capacity(keys.len());
        for key in keys {
            // additional_calls: permission & account registry
            let (authorize_call, additional_calls) =
                key.into_calls(self.account_registry(), account)?;
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
    ///
    /// `maybe_prep_init` should only be `Some`, if we're dealing with the first intent of a
    /// PREPAccount.
    async fn generate_calls(
        &self,
        maybe_prep_init: Option<&CreatableAccount>,
        request: &PrepareCallsParameters,
    ) -> Result<Vec<Call>, RelayError> {
        // Generate all calls that will authorize  keys and set their permissions
        let authorize_calls =
            self.authorize_into_calls(request.capabilities.authorize_keys.clone(), request.from)?;

        // Generate all revoke key calls
        let revoke_calls = request
            .capabilities
            .revoke_keys
            .iter()
            .flat_map(|key| key.clone().into_calls(self.account_registry()));

        // If we are planning to use a session key as the first intent signing key, we need to
        // enable it to register the admin accounts in the AccountRegistry contract.
        //
        // This is done by adding an extra call to the precall to give it permission to do so.
        //
        // We assume that this is the first intent if ANY of the following options is true:
        // * `maybe_prep_init` is `Some` as described in `generate_calls`
        // * `request.from` is `None`. This is the case when the user is signing up and needs to
        //   authorize a session key before even going through PREPAccount generation flow.
        let account_registry_permission = request
            .capabilities
            .authorize_keys
            .iter()
            .filter(|auth| {
                request.capabilities.pre_call
                    && !auth.key.isSuperAdmin
                    && (maybe_prep_init.is_some() || request.from.is_none())
            })
            .map(|auth| {
                Call::set_can_execute(
                    auth.key.key_hash(),
                    self.account_registry(),
                    AccountRegistry::registerCall::SELECTOR.into(),
                    true,
                )
            });

        // If this is the first user intent of this PREPAccount, we need to register the admin
        // accounts into the AccountRegistry contract.
        let account_registry_calls =
            maybe_prep_init.iter().filter(|_| !request.capabilities.pre_call).flat_map(|acc| {
                acc.id_signatures
                    .iter()
                    .map(|id| id.to_call(self.account_registry(), acc.prep.address))
            });

        // Merges all previously generated calls.
        Ok(authorize_calls
            .into_iter()
            .chain(account_registry_permission)
            .chain(account_registry_calls)
            .chain(request.calls.clone())
            .chain(revoke_calls)
            .collect())
    }

    /// Checks if the orchestrator is supported.
    fn is_supported_orchestrator(&self, orchestrator: &Address) -> bool {
        self.orchestrator() == *orchestrator
            || self.legacy_orchestrators().any(|c| c == *orchestrator)
    }

    /// Checks if the account has a supported delegation implementation. If so, returns it.
    async fn has_supported_delegation<P: Provider + Clone>(
        &self,
        account: &Account<P>,
    ) -> Result<Address, RelayError> {
        let address = self.get_delegation_implementation(account).await?;
        if self.delegation_implementation() == address
            || self.legacy_delegations().any(|c| c == address)
        {
            return Ok(address);
        }
        Err(AuthError::InvalidDelegation(address).into())
    }

    /// Ensures the account has the latest delegation implementation. Otherwise, returns error.
    async fn ensure_latest_delegation<P: Provider + Clone>(
        &self,
        account: &Account<P>,
    ) -> Result<(), RelayError> {
        let address = self.has_supported_delegation(account).await?;
        if self.delegation_implementation() != address {
            return Err(AuthError::InvalidDelegation(address).into());
        }
        Ok(())
    }
}

#[async_trait]
impl RelayApiServer for Relay {
    async fn health(&self) -> RpcResult<String> {
        Ok(RELAY_SHORT_VERSION.to_string())
    }

    async fn get_capabilities(&self, chains: Vec<ChainId>) -> RpcResult<RelayCapabilities> {
        let capabilities = try_join_all(chains.into_iter().filter_map(|chain_id| {
            // Relay needs a chain endpoint to support a chain.
            self.inner.chains.get(chain_id)?;

            // Relay needs a list of accepted chain tokens to support a chain.
            let fee_tokens = self.inner.fee_tokens.chain_tokens(chain_id)?.clone();

            Some(async move {
                let fee_tokens = try_join_all(fee_tokens.into_iter().map(|token| {
                    async move {
                        // TODO: only handles eth as native fee token
                        let rate = self
                            .inner
                            .price_oracle
                            .eth_price(token.kind)
                            .await
                            .ok_or(QuoteError::UnavailablePrice(token.address))?;
                        Ok(token.with_rate(rate))
                    }
                }))
                .await?;

                Ok::<_, QuoteError>((
                    chain_id,
                    ChainCapabilities {
                        contracts: self.inner.contracts.clone(),
                        fees: ChainFees {
                            recipient: self.inner.fee_recipient,
                            quote_config: self.inner.quote_config.clone(),
                            tokens: fee_tokens,
                        },
                    },
                ))
            })
        }))
        .await?
        .into_iter()
        .collect();

        Ok(RelayCapabilities(capabilities))
    }

    async fn prepare_create_account(
        &self,
        request: PrepareCreateAccountParameters,
    ) -> RpcResult<PrepareCreateAccountResponse> {
        // Creating account should have at least one admin key.
        if request.capabilities.authorize_keys.is_empty() {
            return Err(KeysError::MissingAdminKey)?;
        }

        // Creating account should only have admin keys.
        if request.capabilities.authorize_keys.iter().any(|key| !key.key.isSuperAdmin) {
            return Err(KeysError::OnlyAdminKeyAllowed)?;
        }

        // Generate all calls that will authorize keys and set their permissions
        let init_calls =
            self.authorize_into_calls(request.capabilities.authorize_keys.clone(), None)?;

        let account = PREPAccount::initialize(request.capabilities.delegation, init_calls);
        let prep_address = account.address;

        let digests = request
            .capabilities
            .authorize_keys
            .iter()
            .filter(|&k| k.key.isSuperAdmin)
            .map(|k| k.key.id_digest(prep_address))
            .collect();

        Ok(PrepareCreateAccountResponse {
            context: CreateAccountContext { account, chain_id: request.chain_id },
            address: prep_address,
            digests,
            capabilities: request.capabilities.into_response(),
        })
    }

    async fn create_account(
        &self,
        request: CreateAccountParameters,
    ) -> RpcResult<Vec<KeyHashWithID>> {
        // Ensure PREPAccount and signatures are valid and not empty.
        let keys = request.validate_and_get_key_ids()?;

        // IDs need to either be new in the registry OR have zero accounts associated.
        let accounts = AccountRegistryCalls::id_infos(
            keys.iter().map(|key| key.id).collect(),
            self.account_registry(),
            self.provider(request.context.chain_id)?,
        )
        .await?;

        for (key, accounts) in keys.iter().zip(accounts) {
            if accounts.is_some_and(|(_, addresses)| !addresses.is_empty()) {
                return Err(RelayError::Keys(KeysError::TakenKeyId(key.id)).into());
            }
        }

        // Ensure it's using the lasted delegation implementation.
        self.ensure_latest_delegation(
            &Account::new(
                request.context.account.address,
                self.provider(request.context.chain_id)?,
            )
            .with_delegation_override(request.context.account.signed_authorization.address()),
        )
        .await?;

        // Write to storage to be used on prepareCalls
        self.inner
            .storage
            .write_prep(CreatableAccount::new(request.context.account, keys.clone()))
            .await?;

        Ok(keys)
    }

    async fn get_accounts(
        &self,
        request: GetAccountsParameters,
    ) -> RpcResult<Vec<AccountResponse>> {
        let provider = self.provider(request.chain_id)?;

        let mut accounts =
            AccountRegistryCalls::accounts(request.id, self.account_registry(), provider.clone())
                .await?;

        if accounts.is_none() {
            // Only read from storage if the onchain mapping does not exist. It's possible that the
            // original key has been revoked onchain, and we don't want to return it as
            // a response.
            let key_accounts = self.inner.storage.read_accounts_from_id(&request.id).await?;

            // For the same reason of the above, we only want to return locally stored accounts
            // that have NOT been deployed.
            let stored_accounts: Vec<Address> =
                try_join_all(key_accounts.into_iter().map(async |account| {
                    Ok::<_, RelayError>(
                        (!Account::new(account, &provider).is_delegated().await?)
                            .then_some(account),
                    )
                }))
                .await?
                .into_iter()
                .flatten()
                .collect();

            if !stored_accounts.is_empty() {
                accounts = Some(stored_accounts);
            }
        }

        let Some(accounts) = accounts else {
            return Err(KeysError::UnknownKeyId(request.id).into());
        };

        try_join_all(accounts.into_iter().map(async |address| {
            let account = Account::new(address, provider.clone());
            let (delegation, keys) = try_join!(
                self.get_delegation_implementation(&account),
                self.get_keys(GetKeysParameters { address, chain_id: request.chain_id })
            )?;

            Ok(AccountResponse { address, delegation, keys })
        }))
        .await
    }

    async fn get_keys(&self, request: GetKeysParameters) -> RpcResult<Vec<AuthorizeKeyResponse>> {
        Ok(self.get_keys(request).await?)
    }

    async fn prepare_calls(
        &self,
        request: PrepareCallsParameters,
    ) -> RpcResult<PrepareCallsResponse> {
        // Checks calls and precall calls in the request
        request.check_calls(self.delegation_implementation())?;

        let provider = self.provider(request.chain_id)?;

        // Find if the address is delegated or if we have a PREPAccount in storage that can use to
        // delegate.
        let mut maybe_prep = None;
        if let Some(from) = &request.from {
            if !Account::new(*from, provider.clone()).is_delegated().await? {
                maybe_prep = Some(
                    self.inner
                        .storage
                        .read_prep(from)
                        .await
                        .map_err(|e| RelayError::InternalError(e.into()))?
                        .ok_or_else(|| {
                            RelayError::Auth(AuthError::EoaNotDelegated(*from).boxed())
                        })?,
                );
            }
        }

        // Generate all requested calls.
        let calls = self.generate_calls(maybe_prep.as_ref(), &request).await?;

        // Get next available nonce for DEFAULT_SEQUENCE_KEY
        let nonce = request.get_nonce(maybe_prep.as_ref(), &provider).await?;

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
                            init_data: maybe_prep.as_ref().map(|acc| acc.prep.init_data()),
                            payer: request.capabilities.meta.fee_payer,
                            pre_calls: request.capabilities.pre_calls.clone(),
                        },
                        chain_id: request.chain_id,
                        prehash: request_key.prehash,
                    },
                    request.capabilities.meta.fee_token,
                    maybe_prep.as_ref().map(|acc| acc.prep.signed_authorization.address),
                    key,
                    false,
                )
                .await
                .inspect_err(|err| {
                    error!(
                        %err,
                        "Failed to create a quote.",
                    );
                })?;

            (asset_diff, PrepareCallsContext::with_quote(quote))
        };

        // Calculate the eip712 digest that the user will need to sign.
        let (digest, typed_data) = context
            .compute_eip712_data(self.orchestrator(), &provider)
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

    async fn prepare_upgrade_account(
        &self,
        request: PrepareUpgradeAccountParameters,
    ) -> RpcResult<PrepareCallsResponse> {
        let provider = self.provider(request.chain_id)?;

        // Upgrading account should have at least one authorize admin key since
        // `wallet_prepareCalls` only accepts non-root keys.
        if !request.capabilities.authorize_keys.iter().any(|key| key.key.isSuperAdmin) {
            return Err(KeysError::MissingAdminKey)?;
        }

        // Generate all calls that will authorize keys and set their permissions
        let calls = self.authorize_into_calls(
            request.capabilities.authorize_keys.clone(),
            Some(request.address),
        )?;

        // Override the account with the 7702 delegation. We need to do this, since this might be a
        // returning account, and thus, nonce will not be zero
        let account = Account::new(request.address, &provider)
            .with_delegation_override(&request.capabilities.delegation);

        let (nonce, _) = try_join!(
            async { account.get_nonce().await.map_err(RelayError::from) },
            self.ensure_latest_delegation(&account)
        )?;

        // Before simulation, we state override with a mock delegation key
        // instead of the the real one to match the storage writes of
        // the live transaction. Thus, avoiding under-estimating gas.
        let mock_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)
            .map_err(RelayError::from)
            .and_then(|k| k.ok_or_else(|| RelayError::Keys(KeysError::UnsupportedKeyType)))?;

        // Call estimateFee to give us a quote with a complete intent that the user can sign
        let (asset_diff, quote) = self
            .estimate_fee(
                PartialAction {
                    intent: PartialIntent {
                        eoa: request.address,
                        execution_data: calls.abi_encode().into(),
                        nonce,
                        init_data: None,
                        payer: request.capabilities.fee_payer,
                        pre_calls: vec![],
                    },
                    chain_id: request.chain_id,
                    // signed by the eoa root key
                    prehash: false,
                },
                request.capabilities.fee_token,
                Some(request.capabilities.delegation),
                mock_key.key().clone(),
                true,
            )
            .await
            .inspect_err(|err| {
                error!(
                    %err,
                    "Failed to create a quote.",
                );
            })?;

        // Calculate the eip712 digest that the user will need to sign.
        let (digest, typed_data) = quote
            .ty()
            .intent
            .compute_eip712_data(self.orchestrator(), &provider)
            .await
            .map_err(RelayError::from)?;

        let response = PrepareCallsResponse {
            context: PrepareCallsContext::with_quote(quote),
            digest,
            typed_data,
            capabilities: PrepareCallsResponseCapabilities {
                authorize_keys: request
                    .capabilities
                    .authorize_keys
                    .into_iter()
                    .map(|key| key.into_response())
                    .collect::<Vec<_>>(),
                revoke_keys: Vec::new(),
                asset_diff,
            },
            key: None,
        };

        Ok(response)
    }

    async fn send_prepared_calls(
        &self,
        request: SendPreparedCallsParameters,
    ) -> RpcResult<SendPreparedCallsResponse> {
        let SendPreparedCallsParameters { capabilities, context, signature, key } = request;
        let Some(mut quote) = context.take_quote() else {
            return Err(QuoteError::QuoteNotFound.into());
        };

        let intent = &mut quote.ty_mut().intent;

        // Fill Intent with the fee payment signature (if exists).
        intent.paymentSignature = capabilities.fee_signature;

        // Fill Intent with the user signature.
        let key_hash = key.key_hash();
        intent.signature =
            Signature { innerSignature: signature, keyHash: key_hash, prehash: key.prehash }
                .abi_encode_packed()
                .into();

        // Set non-eip712 payment fields. Since they are not included into the signature so we need
        // to enforce it here.
        intent.set_legacy_payment_amount(intent.prePaymentMaxAmount);

        // If there's initData we need to fetch the signed authorization from storage.
        let authorization = if intent.initData.is_empty() {
            None
        } else {
            self.inner
                .storage
                .read_prep(&intent.eoa)
                .await
                .map(|opt| opt.map(|acc| acc.prep.signed_authorization))?
        };

        // Broadcast transaction with Intent
        let id = self.send_action(quote, authorization).await.inspect_err(|err| {
            error!(
                %err,
                "Failed to submit call bundle transaction.",
            );
        })?;

        // todo: for now it's fine, but this will change in the future.
        let response = SendPreparedCallsResponse { id };

        Ok(response)
    }

    async fn upgrade_account(
        &self,
        request: UpgradeAccountParameters,
    ) -> RpcResult<UpgradeAccountResponse> {
        let UpgradeAccountParameters { context, signature, authorization } = request;
        let Some(mut quote) = context.take_quote() else {
            return Err(QuoteError::QuoteNotFound.into());
        };

        // Ensure that we have a signed delegation and its address matches the quote's.
        if quote.ty().authorization_address != Some(authorization.address) {
            return Err(AuthError::InvalidAuthAddress {
                expected: quote.ty().authorization_address.expect("should exist"),
                got: authorization.address,
            }
            .into());
        }

        let intent = &mut quote.ty_mut().intent;

        // Fill Intent with the user signature.
        intent.signature = signature.as_bytes().into();

        // Broadcast transaction with Intent
        let id = self.send_action(quote, Some(authorization)).await.inspect_err(|err| {
            error!(
                %err,
                "Failed to submit upgrade account transaction.",
            );
        })?;

        // TODO: for now it's fine, but this will change in the future.
        let response = UpgradeAccountResponse { bundles: vec![SendPreparedCallsResponse { id }] };

        Ok(response)
    }

    async fn get_calls_status(&self, id: BundleId) -> RpcResult<CallsStatus> {
        let tx_ids = self.inner.storage.get_bundle_transactions(id).await?;
        let tx_statuses =
            try_join_all(tx_ids.into_iter().map(|tx_id| async move {
                self.inner.storage.read_transaction_status(tx_id).await
            }))
            .await?;

        let any_pending = tx_statuses.iter().flatten().any(|(_, status)| {
            matches!(status, TransactionStatus::InFlight | TransactionStatus::Pending(_))
        });
        let any_failed = tx_statuses
            .iter()
            .flatten()
            .any(|(_, status)| matches!(status, TransactionStatus::Failed(_)));

        let receipts = try_join_all(
            tx_statuses
                .iter()
                .flatten()
                .flat_map(|(chain_id, status)| {
                    Some((chain_id, TransactionStatus::tx_hash(status)?))
                })
                .map(|(chain_id, tx_hash)| async move {
                    let provider = self.inner.chains.get(*chain_id).unwrap().provider;
                    Ok::<_, RelayError>((
                        chain_id,
                        provider
                            .get_transaction_receipt(tx_hash)
                            .await
                            .map_err(RelayError::from)?,
                    ))
                }),
        )
        .await?;

        // filter out non existing receipts, as we can assume this means the tx is pending, which is
        // handled separately
        let receipts: Vec<(ChainId, TransactionReceipt)> = receipts
            .into_iter()
            .flat_map(|(chain_id, receipt)| Some((*chain_id, receipt?)))
            .collect();

        // note(onbjerg): this currently rests on the assumption that there is only one intent per
        // transaction, and that each transaction in a bundle originates from a single user
        //
        // in the future, this may not be the case, and we need to store the originating users
        // address in the txs table.
        //
        // note that we also assume that failure to decode a log as `IntentExecuted` means the
        // intent failed
        let any_reverted = receipts.iter().any(|(_, receipt)| {
            receipt
                .decoded_log::<IntentExecuted>()
                .is_none_or(|evt| evt.err != ORCHESTRATOR_NO_ERROR)
        });
        let all_reverted = receipts.iter().all(|(_, receipt)| {
            receipt
                .decoded_log::<IntentExecuted>()
                .is_none_or(|evt| evt.err != ORCHESTRATOR_NO_ERROR)
        });

        let status = if any_failed {
            CallStatusCode::Failed
        } else if any_pending {
            CallStatusCode::Pending
        } else if all_reverted {
            CallStatusCode::Reverted
        } else if any_reverted {
            CallStatusCode::PartiallyReverted
        } else {
            CallStatusCode::Confirmed
        };

        Ok(CallsStatus {
            id,
            status,
            receipts: receipts
                .into_iter()
                .map(|(chain_id, receipt)| CallReceipt {
                    chain_id,
                    logs: receipt.inner.logs().to_vec(),
                    status: receipt.status().into(),
                    block_hash: receipt.block_hash,
                    block_number: receipt.block_number,
                    gas_used: receipt.gas_used,
                    transaction_hash: receipt.transaction_hash,
                })
                .collect(),
        })
    }

    async fn verify_signature(
        &self,
        parameters: VerifySignatureParameters,
    ) -> RpcResult<VerifySignatureResponse> {
        let VerifySignatureParameters { key_id_or_address, digest, signature, chain_id } =
            parameters;

        let provider = self.provider(chain_id)?;

        let (mut id_infos, is_delegated) = try_join!(
            AccountRegistryCalls::id_infos(
                vec![key_id_or_address],
                self.account_registry(),
                provider.clone(),
            ),
            async { Account::new(key_id_or_address, &provider).is_delegated().await }
        )?;

        // If we are requested to verify a signature against an account, we don't know the key hash,
        // otherwise we do as it can be fetched by key id.
        let maybe_account_and_key_hash = if is_delegated {
            Some((key_id_or_address, None))
        } else {
            id_infos
                .pop()
                .flatten()
                .and_then(|(key_hash, mut accounts)| Some((accounts.pop()?, Some(key_hash))))
        };

        // If we were able to fetch account from registry, proceed with it
        if let Some((account, maybe_key_hash)) = maybe_account_and_key_hash {
            let account = Account::new(account, &provider);

            // Prepare signatures to verify
            let signatures = if let Some(key_hash) = maybe_key_hash {
                // Just one signature if we know the key hash
                vec![Signature { innerSignature: signature, keyHash: key_hash, prehash: false }]
            } else {
                // Otherwise fetch keys from account and try verifying signature against all of them
                account
                    .keys()
                    .await
                    .map_err(RelayError::from)?
                    .into_iter()
                    // We only support verifying signatures from admin keys, session keys are
                    // assumed to never sign messages.
                    .filter_map(|(key_hash, key)| {
                        if key.isSuperAdmin {
                            Some(Signature {
                                innerSignature: signature.clone(),
                                keyHash: key_hash,
                                prehash: false,
                            })
                        } else {
                            None
                        }
                    })
                    .collect()
            };

            let results = try_join_all(
                signatures
                    .into_iter()
                    .map(|signature| account.validate_signature(digest, signature)),
            )
            .await
            .map_err(RelayError::from)?;

            let key_hash = results.iter().find_map(|result| {
                let &Some(hash) = result else {
                    return None;
                };

                maybe_key_hash.is_none_or(|key_hash| key_hash == hash).then_some(hash)
            });

            let proof = key_hash.map(|key_hash| ValidSignatureProof {
                account: account.address(),
                key_hash,
                prep_init_data: None,
                id_signature: None,
            });

            return Ok(VerifySignatureResponse { valid: proof.is_some(), proof });
        }

        let (mut account, maybe_key_hash) =
            if let Some(account) = self.inner.storage.read_prep(&key_id_or_address).await? {
                (account, None)
            } else {
                self.inner
                    .storage
                    // Read all stored accounts corresponding to the key id.
                    .read_accounts_from_id(&key_id_or_address)
                    .await?
                    .into_iter()
                    // Filter out accounts that are already delegated.
                    .map(async |account| {
                        if !Account::new(account, &provider).is_delegated().await? {
                            Ok::<_, RelayError>(Some(account))
                        } else {
                            Ok(None)
                        }
                    })
                    .collect::<TryJoinAll<_>>()
                    .await?
                    .into_iter()
                    .flatten()
                    // Read the prep accounts from storage.
                    .map(async |account| self.inner.storage.read_prep(&account).await)
                    .collect::<TryJoinAll<_>>()
                    .await?
                    .into_iter()
                    .flatten()
                    // Find account containing the key id and fetch the key hash from it.
                    .find_map(|acc| {
                        let key_hash =
                            acc.id_signatures.iter().find(|sig| sig.id == key_id_or_address)?.hash;

                        Some((acc, Some(key_hash)))
                    })
                    .ok_or(KeysError::UnknownKeyId(key_id_or_address))?
            };

        // Prepare signatures to verify.
        let signatures = if let Some(key_hash) = maybe_key_hash {
            // Just one signature if we know the key hash
            vec![Signature { innerSignature: signature, keyHash: key_hash, prehash: false }]
        } else {
            // Signatures of all admin keys otherwise
            account
                .id_signatures
                .iter()
                .map(|sig| Signature {
                    innerSignature: signature.clone(),
                    keyHash: sig.hash,
                    prehash: false,
                })
                .collect()
        };

        // Prepare initData for initializePREP call.
        let init_data = account.prep.init_data();

        let results = try_join_all(signatures.into_iter().map(async |signature| {
            Account::new(account.address(), &provider)
                .with_delegation_override(&account.prep.signed_authorization.address)
                .initialize_and_validate_signature(init_data.clone(), digest, signature)
                .await
        }))
        .await
        .map_err(RelayError::from)?;

        let key_hash = results.iter().find_map(|result| {
            let &Some(hash) = result else {
                return None;
            };

            maybe_key_hash.is_none_or(|key_hash| key_hash == hash).then_some(hash)
        });

        let proof = key_hash.map(|key_hash| ValidSignatureProof {
            account: account.address(),
            key_hash,
            prep_init_data: Some(init_data),
            id_signature: account.id_signatures.pop().map(|sig| sig.signature),
        });

        return Ok(VerifySignatureResponse { valid: proof.is_some(), proof });
    }
}

/// Implementation of the Ithaca `relay_` namespace.
#[derive(Debug)]
struct RelayInner {
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

impl Relay {
    /// The orchestrator address.
    pub fn orchestrator(&self) -> Address {
        self.inner.contracts.orchestrator.address
    }

    /// Previously deployed orchestrators.
    pub fn legacy_orchestrators(&self) -> impl Iterator<Item = Address> {
        self.inner.contracts.legacy_orchestrators.iter().map(|c| c.address)
    }

    /// Previously deployed delegation implementations.
    pub fn legacy_delegations(&self) -> impl Iterator<Item = Address> {
        self.inner.contracts.legacy_delegations.iter().map(|c| c.address)
    }

    /// The delegation proxy address.
    pub fn delegation_proxy(&self) -> Address {
        self.inner.contracts.delegation_proxy.address
    }

    /// The delegation implementation address.
    pub fn delegation_implementation(&self) -> Address {
        self.inner.contracts.delegation_implementation.address
    }

    /// The account registry address.
    pub fn account_registry(&self) -> Address {
        self.inner.contracts.account_registry.address
    }

    /// The simulator address.
    pub fn simulator(&self) -> Address {
        self.inner.contracts.simulator.address
    }
}

/// Approximates the intrinsic cost of a transaction.
///
/// This function assumes Prague rules.
fn approx_intrinsic_cost(input: &[u8], has_auth: bool) -> u64 {
    let zero_data_len = input.iter().filter(|v| **v == 0).count() as u64;
    let non_zero_data_len = input.len() as u64 - zero_data_len;
    let non_zero_data_multiplier = 4; // as defined in istanbul
    let standard_token_cost = 4;
    let tokens = zero_data_len + non_zero_data_len * non_zero_data_multiplier;

    // for 7702 designations there is an additional gas charge
    //
    // note: this is not entirely accurate, as there is also a gas refund in 7702, but at this
    // point it is not possible to compute the gas refund, so it is an overestimate, as we also
    // need to charge for the account being presumed empty.
    let auth_cost = if has_auth { PER_EMPTY_ACCOUNT_COST } else { 0 };

    21000 + auth_cost + tokens * standard_token_cost
}
