//! # Ithaca Relay RPC
//!
//! Implementations of a custom `relay_` namespace.
//!
//! - `relay_estimateFee` for estimating [`UserOp`] fees.
//! - `relay_sendAction` that can perform service-sponsored [EIP-7702][eip-7702] delegations and
//!   send other service-sponsored UserOp's on behalf of EOAs with delegated code.
//!
//! [eip-7702]: https://eips.ethereum.org/EIPS/eip-7702

use crate::{
    eip712::compute_eip712_data,
    types::{
        AccountRegistry::AccountRegistryCalls,
        AssetDiff, Call, Key, KeyHash, KeyHashWithID,
        rpc::{CreateAccountContext, RelaySettings},
    },
    version::RELAY_SHORT_VERSION,
};
use alloy::{
    eips::eip7702::{
        SignedAuthorization,
        constants::{EIP7702_DELEGATION_DESIGNATOR, PER_AUTH_BASE_COST, PER_EMPTY_ACCOUNT_COST},
    },
    primitives::{Address, Bytes, ChainId, TxHash, U256, bytes},
    providers::{DynProvider, Provider},
    rpc::types::state::{AccountOverride, StateOverridesBuilder},
    sol_types::SolValue,
};
use futures_util::{
    TryFutureExt,
    future::{try_join_all, try_join3},
};
use jsonrpsee::{
    core::{RpcResult, async_trait},
    proc_macros::rpc,
};
use std::{sync::Arc, time::SystemTime};
use tracing::{debug, error};

use crate::{
    chains::{Chain, Chains},
    config::QuoteConfig,
    error::{AuthError, KeysError, QuoteError, RelayError},
    price::PriceOracle,
    signers::DynSigner,
    storage::{RelayStorage, StorageApi},
    transactions::{RelayTransaction, TransactionStatus},
    types::{
        Account, CreatableAccount, Entry, FeeTokens, KeyWith712Signer, PREPAccount, PartialAction,
        PartialUserOp, Quote, Signature, SignedQuote, UserOp,
        rpc::{
            AccountResponse, AuthorizeKey, AuthorizeKeyResponse, BundleId, CallsStatus,
            CreateAccountParameters, GetAccountsParameters, GetKeysParameters,
            PrepareCallsParameters, PrepareCallsResponse, PrepareCallsResponseCapabilities,
            PrepareCreateAccountParameters, PrepareCreateAccountResponse,
            PrepareUpgradeAccountParameters, SendPreparedCallsParameters,
            SendPreparedCallsResponse, UpgradeAccountParameters, UpgradeAccountResponse,
        },
    },
};

/// Ithaca `relay_` RPC namespace.
#[rpc(server, client, namespace = "relay")]
pub trait RelayApi {
    /// Checks the health of the relay and returns its version.
    #[method(name = "health", aliases = ["health"])]
    async fn health(&self) -> RpcResult<RelaySettings>;

    /// Get all supported fee tokens by chain.
    #[method(name = "feeTokens", aliases = ["wallet_feeTokens"])]
    async fn fee_tokens(&self) -> RpcResult<FeeTokens>;

    /// Estimates the fee a user would have to pay for the given action in the given fee token.
    #[method(name = "estimateFee", aliases = ["wallet_estimateFee"])]
    async fn estimate_fee(
        &self,
        request: PartialAction,
        token: Address,
        authorization_address: Option<Address>,
        key: Key,
    ) -> RpcResult<(AssetDiff, SignedQuote)>;

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
}

/// Implementation of the Ithaca `relay_` namespace.
#[derive(Debug)]
pub struct Relay {
    inner: Arc<RelayInner>,
}

impl Relay {
    /// Create a new Ithaca relay module.
    pub fn new(
        entrypoint: Address,
        chains: Chains,
        quote_signer: DynSigner,
        quote_config: QuoteConfig,
        price_oracle: PriceOracle,
        fee_tokens: FeeTokens,
        storage: RelayStorage,
    ) -> Self {
        let inner = RelayInner {
            entrypoint,
            chains,
            fee_tokens,
            quote_signer,
            quote_config,
            price_oracle,
            storage,
        };
        Self { inner: Arc::new(inner) }
    }

    async fn send_action(
        &self,
        quote: SignedQuote,
        authorization: Option<SignedAuthorization>,
    ) -> RpcResult<TxHash> {
        let Chain { provider, transactions } = self
            .inner
            .chains
            .get(quote.ty().chain_id)
            .ok_or(RelayError::UnsupportedChain(quote.ty().chain_id))?;

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
                .get_transaction_count(quote.ty().op.eoa)
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
            let account = Account::new(quote.ty().op.eoa, provider);
            if !account.is_delegated().await? {
                return Err(AuthError::EoaNotDelegated(quote.ty().op.eoa).into());
            }
        }

        // this can be done by just verifying the signature & userop hash against the rfq
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

        let tx = RelayTransaction::new(quote, self.inner.entrypoint, authorization);

        // TODO: Right now we only support a single transaction per action and per bundle, so we can
        // simply set BundleId to TxId. Eventually bundles might contain multiple transactions and
        // this is already supported by current storage API.
        let bundle_id = BundleId(*tx.id);
        self.inner.storage.add_bundle_tx(bundle_id, tx.id).await?;

        let mut rx = transactions.send_transaction(tx);

        // Wait for the transaction hash.
        // TODO: get rid of it and use wallet_getCallsStatus instead. This might not work well if we
        // resubmit transaction with a higher fee.
        while let Some(status) = rx.recv().await {
            match status {
                TransactionStatus::Pending(hash) | TransactionStatus::Confirmed(hash) => {
                    return Ok(hash);
                }
                TransactionStatus::InFlight => continue,
                TransactionStatus::Failed(err) => {
                    return Err(RelayError::InternalError(err.into()).into());
                }
            }
        }

        Err(RelayError::InternalError(eyre::eyre!("transaction failed")).into())
    }

    /// Get keys from an account.
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
    async fn get_keys_onchain(
        &self,
        request: GetKeysParameters,
    ) -> Result<Vec<AuthorizeKeyResponse>, RelayError> {
        let account = Account::new(request.address, self.provider(request.chain_id)?);

        if !account.is_delegated().await? {
            return Err(AuthError::EoaNotDelegated(request.address).boxed().into());
        }

        // Get all keys from account
        let keys = account.keys().await.map_err(RelayError::from)?;

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
                key.into_calls(self.inner.entrypoint, account)?;
            calls.push(authorize_call);
            calls.extend(additional_calls);
        }
        Ok(calls)
    }

    /// Given a key hash and a list of [`UserOp`], it tries to find a key from a requested EOA.
    ///
    /// If it cannot find it, it will attempt to fetch it from storage or on-chain.
    async fn try_find_key(
        &self,
        from: Address,
        key_hash: KeyHash,
        ops: &[UserOp],
        chain_id: ChainId,
    ) -> Result<Option<Key>, RelayError> {
        for pre_op in ops {
            if let Some(key) =
                pre_op.authorized_keys()?.iter().find(|key| key.key_hash() == key_hash)
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
}

#[async_trait]
impl RelayApiServer for Relay {
    async fn health(&self) -> RpcResult<RelaySettings> {
        Ok(RelaySettings {
            version: RELAY_SHORT_VERSION.to_string(),
            entrypoint: self.inner.entrypoint,
            quote_config: self.inner.quote_config.clone(),
        })
    }

    async fn fee_tokens(&self) -> RpcResult<FeeTokens> {
        Ok(self.inner.fee_tokens.clone())
    }

    async fn estimate_fee(
        &self,
        request: PartialAction,
        token: Address,
        authorization_address: Option<Address>,
        account_key: Key,
    ) -> RpcResult<(AssetDiff, SignedQuote)> {
        let provider = self.provider(request.chain_id)?;
        let Some(token) = self.inner.fee_tokens.find(request.chain_id, &token) else {
            return Err(QuoteError::UnsupportedFeeToken(token).into());
        };

        // create key
        let mock_signer_address = self.inner.quote_signer.address();
        let mock_key = KeyWith712Signer::random_admin(account_key.keyType)
            .map_err(RelayError::from)
            .and_then(|k| k.ok_or_else(|| RelayError::Keys(KeysError::UnsupportedKeyType)))?;

        // mocking key storage for the eoa, and the balance for the mock signer
        let overrides = StateOverridesBuilder::with_capacity(2)
            .append(
                mock_signer_address,
                AccountOverride::default().with_balance(U256::MAX.div_ceil(2.try_into().unwrap())),
            )
            // simulateExecute requires it, so the function can only be called under a testing
            // environment
            .append(
                self.inner.quote_signer.address(),
                AccountOverride::default().with_balance(U256::MAX),
            )
            .append(
                request.op.eoa,
                AccountOverride::default()
                    .with_balance(U256::MAX.div_ceil(2.try_into().unwrap()))
                    .with_state_diff(account_key.storage_slots())
                    // we manually etch the 7702 designator since we do not have a signed auth item
                    .with_code_opt(authorization_address.map(|addr| {
                        Bytes::from([&EIP7702_DELEGATION_DESIGNATOR, addr.as_slice()].concat())
                    })),
            )
            .build();

        // load account and entrypoint
        let entrypoint =
            Entry::new(self.inner.entrypoint, provider.clone()).with_overrides(overrides.clone());

        let (nonce, native_fee_estimate, eth_price) = try_join3(
            // fetch nonce if not specified
            async {
                if let Some(nonce) = request.op.nonce {
                    Ok(nonce)
                } else {
                    entrypoint.get_nonce(request.op.eoa).map_err(RelayError::from).await
                }
            },
            // fetch chain fees
            provider.estimate_eip1559_fees().map_err(RelayError::from),
            // fetch price in eth
            async {
                // TODO: only handles eth as native fee token
                Ok(self.inner.price_oracle.eth_price(token.coin).await)
            },
        )
        .await?;

        let gas_price = U256::from(native_fee_estimate.max_fee_per_gas);
        let Some(eth_price) = eth_price else {
            return Err(QuoteError::UnavailablePrice(token.address).into());
        };

        // fill userop
        let mut op = UserOp {
            eoa: request.op.eoa,
            executionData: request.op.execution_data.clone(),
            nonce,
            paymentToken: token.address,
            // this will force the simulation to go through payment code paths, and get a better
            // estimation.
            paymentAmount: U256::from(1),
            paymentMaxAmount: U256::from(1),
            paymentPerGas: (gas_price * U256::from(10u128.pow(token.decimals as u32))) / eth_price,
            // we intentionally do not use the maximum amount of gas since the contracts add a small
            // overhead when checking if there is sufficient gas for the op
            combinedGas: U256::from(100_000_000),
            initData: request.op.init_data.unwrap_or_default(),
            encodedPreOps: request
                .op
                .pre_ops
                .into_iter()
                .map(|pre_op| pre_op.abi_encode().into())
                .collect(),
            ..Default::default()
        };

        // sign userop
        let signature = mock_key
            .sign_typed_data(
                &op.as_eip712().map_err(RelayError::from)?,
                &entrypoint.eip712_domain(op.is_multichain()).await.map_err(RelayError::from)?,
            )
            .await
            .map_err(RelayError::from)?;

        op.signature = Signature {
            innerSignature: signature,
            keyHash: account_key.key_hash(),
            prehash: account_key.keyType.is_p256(), // WebCrypto P256 uses prehash
        }
        .abi_encode_packed()
        .into();

        // we estimate gas and fees
        let (asset_diff, mut gas_estimate) =
            entrypoint.simulate_execute(self.inner.quote_signer.address(), &op).await?;

        // for 7702 designations there is an additional gas charge
        //
        // note: this is not entirely accurate, as there is also a gas refund in 7702, but at this
        // point it is not possible to compute the gas refund, so it is an overestimate, as we also
        // need to charge for the account being presumed empty.
        if authorization_address.is_some() {
            gas_estimate.tx += PER_AUTH_BASE_COST + PER_EMPTY_ACCOUNT_COST;
        }

        // Add some leeway, since the actual simulation may no be enough.
        // todo: re-evaluate if this is still necessary
        gas_estimate.op += self.inner.quote_config.user_op_buffer();
        gas_estimate.tx += self.inner.quote_config.user_op_buffer();
        gas_estimate.tx += self.inner.quote_config.tx_buffer();

        debug!(eoa = %request.op.eoa, gas_estimate = ?gas_estimate, "Estimated operation");

        // Fill combinedGas and empty dummy signature
        op.combinedGas = U256::from(gas_estimate.op);
        op.signature = bytes!("");

        // Calculate amount with updated paymentPerGas
        op.paymentAmount = op.paymentPerGas * op.combinedGas;
        op.paymentMaxAmount = op.paymentAmount;

        let quote = Quote {
            chain_id: request.chain_id,
            op,
            tx_gas: gas_estimate.tx,
            native_fee_estimate,
            ttl: SystemTime::now()
                .checked_add(self.inner.quote_config.ttl)
                .expect("should never overflow"),
            authorization_address,
        };
        let sig = self
            .inner
            .quote_signer
            .sign_hash(&quote.digest())
            .await
            .map_err(|err| RelayError::InternalError(err.into()))?;

        Ok((asset_diff, quote.into_signed(sig)))
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
            self.inner.entrypoint,
            self.provider(request.context.chain_id)?,
        )
        .await?;

        for (key, accounts) in keys.iter().zip(accounts) {
            if accounts.is_some_and(|(_, addresses)| !addresses.is_empty()) {
                return Err(RelayError::Keys(KeysError::TakenKeyId(key.id)).into());
            }
        }

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
            AccountRegistryCalls::accounts(request.id, self.inner.entrypoint, provider.clone())
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
            Ok(AccountResponse {
                address,
                keys: self
                    .get_keys(GetKeysParameters { address, chain_id: request.chain_id })
                    .await?,
            })
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
        let provider = self.provider(request.chain_id)?;

        // Generate all calls that will authorize keys and set their permissions
        let authorize_calls = self.authorize_into_calls(
            request.capabilities.authorize_keys.clone(),
            Some(request.from),
        )?;

        let revoke_calls = request
            .capabilities
            .revoke_keys
            .iter()
            .flat_map(|key| key.clone().into_calls(self.inner.entrypoint));

        // Find the key that authorizes this userop
        let Some(key) = self
            .try_find_key(
                request.from,
                request.capabilities.meta.key_hash,
                &request.capabilities.pre_ops,
                request.chain_id,
            )
            .await?
        else {
            return Err(KeysError::UnknownKeyHash(request.capabilities.meta.key_hash).into());
        };

        // Find if the address is delegated or if we have a PREPAccount in storage that can use to
        // delegate.
        let account = Account::new(request.from, provider.clone());
        let maybe_prep = if !account.is_delegated().await? {
            Some(
                self.inner
                    .storage
                    .read_prep(&request.from)
                    .await
                    .map_err(|err| RelayError::InternalError(err.into()))?
                    .ok_or_else(|| {
                        RelayError::Auth(AuthError::EoaNotDelegated(request.from).boxed())
                    })?,
            )
        } else {
            None
        };

        // Merges authorize, registry(from prepareAccount) and requested calls.
        let all_calls = authorize_calls
            .into_iter()
            .chain(maybe_prep.iter().filter(|_| !request.capabilities.pre_op).flat_map(|acc| {
                acc.id_signatures
                    .iter()
                    .map(|id| id.to_call(self.inner.entrypoint, acc.prep.address))
            }))
            .chain(request.calls)
            .chain(revoke_calls)
            .collect::<Vec<_>>();

        // Call estimateFee to give us a quote with a complete userOp that the user can sign
        let (asset_diff, quote) = self
            .estimate_fee(
                PartialAction {
                    op: PartialUserOp {
                        eoa: request.from,
                        execution_data: all_calls.abi_encode().into(),
                        nonce: request.capabilities.meta.nonce,
                        init_data: maybe_prep.as_ref().map(|acc| acc.prep.init_data()),
                        pre_ops: request.capabilities.pre_ops.clone(),
                    },
                    chain_id: request.chain_id,
                },
                request.capabilities.meta.fee_token,
                maybe_prep.as_ref().map(|acc| acc.prep.signed_authorization.address),
                key,
            )
            .await
            .inspect_err(|err| {
                error!(
                    %err,
                    "Failed to create a quote.",
                );
            })?;

        // Calculate the eip712 digest that the user will need to sign.
        let (digest, typed_data) =
            compute_eip712_data(&quote.ty().op, self.inner.entrypoint, &provider)
                .await
                .map_err(RelayError::from)?;

        let response = PrepareCallsResponse {
            context: quote,
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
        let Some(admin_key) =
            request.capabilities.authorize_keys.iter().find(|key| key.key.isSuperAdmin)
        else {
            return Err(KeysError::MissingAdminKey)?;
        };

        // Generate all calls that will authorize keys and set their permissions
        let calls = self.authorize_into_calls(
            request.capabilities.authorize_keys.clone(),
            Some(request.address),
        )?;

        // Call estimateFee to give us a quote with a complete userOp that the user can sign
        let (asset_diff, quote) = self
            .estimate_fee(
                PartialAction {
                    op: PartialUserOp {
                        eoa: request.address,
                        execution_data: calls.abi_encode().into(),
                        // todo: should probably not be 0 https://github.com/ithacaxyz/relay/issues/193
                        nonce: Some(U256::ZERO),
                        init_data: None,
                        pre_ops: request.capabilities.pre_ops,
                    },
                    chain_id: request.chain_id,
                },
                request.capabilities.fee_token,
                Some(request.capabilities.delegation),
                admin_key.key.clone(),
            )
            .await
            .inspect_err(|err| {
                error!(
                    %err,
                    "Failed to create a quote.",
                );
            })?;

        // Calculate the eip712 digest that the user will need to sign.
        let (digest, typed_data) =
            compute_eip712_data(&quote.ty().op, self.inner.entrypoint, &provider)
                .await
                .map_err(RelayError::from)?;

        let response = PrepareCallsResponse {
            context: quote,
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
        };

        Ok(response)
    }

    async fn send_prepared_calls(
        &self,
        mut request: SendPreparedCallsParameters,
    ) -> RpcResult<SendPreparedCallsResponse> {
        let op = &mut request.context.ty_mut().op;

        // Fill UserOp with the user signature.
        let key_hash = request.signature.key_hash();
        op.signature = Signature {
            innerSignature: request.signature.value,
            keyHash: key_hash,
            prehash: request.signature.prehash,
        }
        .abi_encode_packed()
        .into();

        // Set `paymentAmount`. It is not included into the signature so we need to enforce it here.
        op.paymentAmount = op.paymentMaxAmount;

        // If there's initData we need to fetch the signed authorization from storage.
        let authorization = if op.initData.is_empty() {
            None
        } else {
            self.inner
                .storage
                .read_prep(&op.eoa)
                .await
                .map(|opt| opt.map(|acc| acc.prep.signed_authorization))?
        };

        // Broadcast transaction with UserOp
        let tx_hash =
            self.send_action(request.context, authorization).await.inspect_err(|err| {
                error!(
                    %err,
                    "Failed to submit call bundle transaction.",
                );
            })?;

        // todo: for now it's fine, but this will change in the future.
        let response = SendPreparedCallsResponse { id: tx_hash };

        Ok(response)
    }

    async fn upgrade_account(
        &self,
        mut request: UpgradeAccountParameters,
    ) -> RpcResult<UpgradeAccountResponse> {
        // Ensure that we have a signed delegation and its address matches the quote's.
        if request.context.ty().authorization_address != Some(request.authorization.address) {
            return Err(AuthError::InvalidAuthAddress {
                expected: request.context.ty().authorization_address.expect("should exist"),
                got: request.authorization.address,
            }
            .into());
        }

        let op = &mut request.context.ty_mut().op;

        // Fill UserOp with the user signature.
        op.signature = request.signature.as_bytes().into();

        // Broadcast transaction with UserOp
        let tx_hash = self
            .send_action(request.context, Some(request.authorization))
            .await
            .inspect_err(|err| {
                error!(
                    %err,
                    "Failed to submit upgrade account transaction.",
                );
            })?;

        // TODO: for now it's fine, but this will change in the future.
        let response =
            UpgradeAccountResponse { bundles: vec![SendPreparedCallsResponse { id: tx_hash }] };

        Ok(response)
    }

    async fn get_calls_status(&self, _id: BundleId) -> RpcResult<CallsStatus> {
        todo!()
    }
}

/// Implementation of the Ithaca `relay_` namespace.
#[derive(Debug)]
struct RelayInner {
    /// The entrypoint address.
    entrypoint: Address,
    /// The chains supported by the relay.
    chains: Chains,
    /// Supported fee tokens.
    fee_tokens: FeeTokens,
    /// The signer used to sign quotes.
    quote_signer: DynSigner,
    /// Quote related configuration.
    quote_config: QuoteConfig,
    /// Price oracle.
    price_oracle: PriceOracle,
    /// Storage
    storage: RelayStorage,
}
