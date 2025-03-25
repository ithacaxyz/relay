//! # Ithaca Relay RPC
//!
//! Implementations of a custom `relay_` namespace.
//!
//! - `relay_estimateFee` for estimating [`UserOp`] fees.
//! - `relay_sendAction` that can perform service-sponsored [EIP-7702][eip-7702] delegations and
//!   send other service-sponsored UserOp's on behalf of EOAs with delegated code.
//!
//! [eip-7702]: https://eips.ethereum.org/EIPS/eip-7702

use crate::types::{AccountRegistry::AccountRegistryCalls, rpc::CreateAccountContext};
use alloy::{
    eips::eip7702::{
        SignedAuthorization,
        constants::{EIP7702_DELEGATION_DESIGNATOR, PER_AUTH_BASE_COST, PER_EMPTY_ACCOUNT_COST},
    },
    primitives::{Address, Bytes, ChainId, TxHash, U256, bytes, map::HashSet},
    providers::{DynProvider, Provider},
    rpc::types::state::{AccountOverride, StateOverridesBuilder},
    sol_types::SolValue,
};
use futures_util::{
    TryFutureExt,
    future::{try_join, try_join_all},
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
    eip712::compute_eip712_digest,
    error::{AuthError, KeysError, QuoteError, RelayError},
    price::PriceOracle,
    signers::DynSigner,
    storage::{RelayStorage, StorageApi},
    transactions::{RelayTransaction, TransactionStatus},
    types::{
        Account, CreatableAccount, Entry, FeeTokens, KeyType, KeyWith712Signer, PREPAccount,
        PartialAction, PartialUserOp, Quote, Signature, SignedQuote, UserOp,
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
    /// Checks the health of the relay.
    #[method(name = "health")]
    async fn health(&self) -> RpcResult<()>;

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
        key: KeyType,
    ) -> RpcResult<SignedQuote>;

    /// Prepares an account for the user.
    #[method(name = "prepareCreateAccount", aliases = ["wallet_prepareCreateAccount"])]
    async fn prepare_create_account(
        &self,
        parameters: PrepareCreateAccountParameters,
    ) -> RpcResult<PrepareCreateAccountResponse>;

    /// Initialize an account.
    #[method(name = "createAccount", aliases = ["wallet_createAccount"])]
    async fn create_account(&self, parameters: CreateAccountParameters) -> RpcResult<()>;

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

    // todo: rewrite
    /// Prepares a call bundle for a user.
    #[method(name = "prepareCalls", aliases = ["wallet_prepareCalls"])]
    async fn prepare_calls(
        &self,
        parameters: PrepareCallsParameters,
    ) -> RpcResult<PrepareCallsResponse>;

    // todo: rewrite
    /// Prepares an EOA to be upgraded.
    #[method(name = "prepareUpgradeAccount", aliases = ["wallet_prepareUpgradeAccount"])]
    async fn prepare_upgrade_account(
        &self,
        parameters: PrepareUpgradeAccountParameters,
    ) -> RpcResult<PrepareCallsResponse>;

    // todo: rewrite
    /// Send a signed call bundle.
    #[method(name = "sendPreparedCalls", aliases = ["wallet_sendPreparedCalls"])]
    async fn send_prepared_calls(
        &self,
        parameters: SendPreparedCallsParameters,
    ) -> RpcResult<SendPreparedCallsResponse>;

    // todo: rewrite
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
            // todo: persist auth
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

    async fn get_keys(
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
                    id_signature: None,
                },
            })
            .collect())
    }

    /// Returns the chain [`DynProvider`].
    pub fn provider(&self, chain_id: ChainId) -> Result<DynProvider, RelayError> {
        Ok(self.inner.chains.get(chain_id).ok_or(RelayError::UnsupportedChain(chain_id))?.provider)
    }
}

#[async_trait]
impl RelayApiServer for Relay {
    async fn health(&self) -> RpcResult<()> {
        Ok(())
    }

    async fn fee_tokens(&self) -> RpcResult<FeeTokens> {
        Ok(self.inner.fee_tokens.clone())
    }

    async fn estimate_fee(
        &self,
        request: PartialAction,
        token: Address,
        authorization_address: Option<Address>,
        key_type: KeyType,
    ) -> RpcResult<SignedQuote> {
        let provider = self.provider(request.chain_id)?;
        let Some(token) = self.inner.fee_tokens.find(request.chain_id, &token) else {
            return Err(QuoteError::UnsupportedFeeToken(token).into());
        };

        // create key
        let mock_signer_address = self.inner.quote_signer.address();
        let key = KeyWith712Signer::random_admin(key_type)
            .map_err(RelayError::from)
            .and_then(|k| k.ok_or_else(|| RelayError::Keys(KeysError::UnsupportedKeyType)))?;

        // mocking key storage for the eoa, and the balance for the mock signer
        let overrides = StateOverridesBuilder::with_capacity(2)
            .append(
                mock_signer_address,
                AccountOverride::default().with_balance(U256::MAX.div_ceil(2.try_into().unwrap())),
            )
            .append(
                request.op.eoa,
                AccountOverride::default()
                    .with_state_diff(key.storage_slots())
                    // we manually etch the 7702 designator since we do not have a signed auth item
                    .with_code_opt(authorization_address.map(|addr| {
                        Bytes::from([&EIP7702_DELEGATION_DESIGNATOR, addr.as_slice()].concat())
                    })),
            )
            .build();

        // load account and entrypoint
        let entrypoint =
            Entry::new(self.inner.entrypoint, provider.clone()).with_overrides(overrides.clone());

        // fetch nonce if not specified
        let nonce = if let Some(nonce) = request.op.nonce {
            nonce
        } else {
            entrypoint.get_nonce(request.op.eoa).await.map_err(RelayError::from)?
        };

        // fill userop
        let mut op = UserOp {
            eoa: request.op.eoa,
            executionData: request.op.execution_data.clone(),
            nonce,
            paymentToken: token.address,
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
        let signature = key
            .sign_typed_data(
                &op.as_eip712().map_err(RelayError::from)?,
                &entrypoint.eip712_domain(op.is_multichain()).await.map_err(RelayError::from)?,
            )
            .await
            .map_err(RelayError::from)?;

        op.signature =
            Signature { innerSignature: signature, keyHash: key.key_hash(), prehash: false }
                .abi_encode_packed()
                .into();

        // we estimate gas and fees
        let (mut gas_estimate, native_fee_estimate) = futures_util::try_join!(
            entrypoint.simulate_execute(&op).map_err(RelayError::from),
            provider.estimate_eip1559_fees().map_err(RelayError::from)
        )?;

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

        // Get paymentPerGas
        // TODO: only handles eth as native fee token
        let Some(eth_price) = self.inner.price_oracle.eth_price(token.coin).await else {
            return Err(QuoteError::UnavailablePrice(token.address).into());
        };
        let gas_price = U256::from(native_fee_estimate.max_fee_per_gas);
        op.paymentPerGas = (gas_price * U256::from(10u128.pow(token.decimals as u32))) / eth_price;

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

        Ok(quote.into_signed(sig))
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
        let init_calls = request
            .capabilities
            .authorize_keys
            .iter()
            .flat_map(|key| {
                let (authorize_call, permissions_calls) = key.clone().into_calls();
                std::iter::once(authorize_call).chain(permissions_calls)
            })
            .collect::<Vec<_>>();

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

    async fn create_account(&self, request: CreateAccountParameters) -> RpcResult<()> {
        // Ensure PREPAccount and signatures are valid and not empty.
        request.validate()?;

        // IDs need to either be new in the registry OR have zero accounts associated.
        let accounts = AccountRegistryCalls::id_infos(
            request.signatures.iter().map(|s| s.id).collect(),
            self.inner.entrypoint,
            self.provider(request.context.chain_id)?,
        )
        .await?;

        for (signature, accounts) in request.signatures.iter().zip(accounts) {
            if accounts.is_some_and(|(_, addresses)| !addresses.is_empty()) {
                return Err(RelayError::Keys(KeysError::TakenKeyId(signature.id)).into());
            }
        }

        // Write to storage to be used on prepareCalls
        self.inner
            .storage
            .write_prep(CreatableAccount::new(request.context.account, request.signatures))
            .await?;

        Ok(())
    }

    async fn get_accounts(
        &self,
        request: GetAccountsParameters,
    ) -> RpcResult<Vec<AccountResponse>> {
        let provider = self.provider(request.chain_id)?;

        // Get all accounts from onchain and local storage
        let local_addresses = Box::pin(async move {
            self.inner
                .storage
                .read_accounts_from_id(&request.id)
                .await
                .map_err(RelayError::Storage)
                .map(|accounts| accounts.unwrap_or_default())
        });
        let onchain_addresses = Box::pin(async move {
            let accounts =
                AccountRegistryCalls::id_infos(vec![request.id], self.inner.entrypoint, provider)
                    .await?
                    .pop()
                    .expect("should exist");
            Ok(accounts.map(|(_, accounts)| accounts).unwrap_or_default())
        });

        let (local_addresses, onchain_addresses) =
            try_join(local_addresses, onchain_addresses).await?;

        // Merge local and onchain accounts, ensuring there are no duplicates.
        let account_set: HashSet<_> =
            local_addresses.into_iter().chain(onchain_addresses).collect();

        if account_set.is_empty() {
            return Err(RelayError::Keys(KeysError::UnknownKeyId(request.id)).into());
        }

        try_join_all(account_set.into_iter().map(async |address| {
            let keys = match self
                .get_keys(GetKeysParameters { address, chain_id: request.chain_id })
                .await
            {
                Ok(keys) => keys,
                Err(err) => match err {
                    // Might have been called after createAccount but before its onchain commit.
                    RelayError::Auth(auth_err) if auth_err.is_eoa_not_delegated() => vec![],
                    _ => return Err(err.into()),
                },
            };

            Ok(AccountResponse { address, keys })
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
        // todo: admin or webauthn require Some(signed identifier)
        let authorize_calls = request.capabilities.authorize_keys.iter().flat_map(|key| {
            let (authorize_call, permissions_calls) = key.clone().into_calls();
            std::iter::once(authorize_call).chain(permissions_calls)
        });

        // todo: fetch them from somewhere.
        let revoke_keys = Vec::new();

        // todo: obtain key with permissions from contracts using request.capabilities.meta.key_hash
        // todo: pass key with permissions to estimate_fee instead of keyType
        let key = KeyType::WebAuthnP256;

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
        let all_calls = if request.capabilities.pre_op {
            authorize_calls.chain(request.calls).collect::<Vec<_>>()
        } else {
            authorize_calls
                .chain(maybe_prep.iter().flat_map(|acc| {
                    acc.id_signatures
                        .iter()
                        .map(|id| id.to_call(self.inner.entrypoint, acc.prep.address))
                }))
                .chain(request.calls)
                .collect::<Vec<_>>()
        };

        // Call estimateFee to give us a quote with a complete userOp that the user can sign
        let quote = self
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
        let digest = compute_eip712_digest(&quote.ty().op, self.inner.entrypoint, &provider)
            .await
            .map_err(RelayError::from)?;

        let response = PrepareCallsResponse {
            context: quote,
            digest,
            capabilities: PrepareCallsResponseCapabilities {
                authorize_keys: request
                    .capabilities
                    .authorize_keys
                    .into_iter()
                    .map(|key| key.into_response())
                    .collect::<Vec<_>>(),
                revoke_keys,
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
        if !request.capabilities.authorize_keys.iter().any(|key| key.key.isSuperAdmin) {
            return Err(KeysError::MissingAdminKey)?;
        }

        // Generate all calls that will authorize keys and set their permissions
        // todo: admin or webauthn require Some(signed identifier)
        let calls = request
            .capabilities
            .authorize_keys
            .iter()
            .flat_map(|key| {
                let (authorize_call, permissions_calls) = key.clone().into_calls();
                std::iter::once(authorize_call).chain(permissions_calls)
            })
            .collect::<Vec<_>>();

        // Call estimateFee to give us a quote with a complete userOp that the user can sign
        let quote = self
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
                request
                    .capabilities
                    .authorize_keys
                    .first()
                    .map(|k| k.key_type())
                    .unwrap_or(KeyType::Secp256k1),
            )
            .await
            .inspect_err(|err| {
                error!(
                    %err,
                    "Failed to create a quote.",
                );
            })?;

        // Calculate the eip712 digest that the user will need to sign.
        let digest = compute_eip712_digest(&quote.ty().op, self.inner.entrypoint, &provider)
            .await
            .map_err(RelayError::from)?;

        let response = PrepareCallsResponse {
            context: quote,
            digest,
            capabilities: PrepareCallsResponseCapabilities {
                authorize_keys: request
                    .capabilities
                    .authorize_keys
                    .into_iter()
                    .map(|key| key.into_response())
                    .collect::<Vec<_>>(),
                revoke_keys: Vec::new(),
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
        op.signature = request.signature.value;

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
                    "Failed to submit upgrade account transaction.",
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
