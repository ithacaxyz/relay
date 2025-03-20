//! # Ithaca Relay RPC
//!
//! Implementations of a custom `relay_` namespace.
//!
//! - `relay_estimateFee` for estimating [`UserOp`] fees.
//! - `relay_sendAction` that can perform service-sponsored [EIP-7702][eip-7702] delegations and
//!   send other service-sponsored UserOp's on behalf of EOAs with delegated code.
//!
//! [eip-7702]: https://eips.ethereum.org/EIPS/eip-7702

use alloy::{
    eips::eip7702::{
        SignedAuthorization,
        constants::{
            EIP7702_CLEARED_DELEGATION, EIP7702_DELEGATION_DESIGNATOR, PER_AUTH_BASE_COST,
            PER_EMPTY_ACCOUNT_COST,
        },
    },
    primitives::{Address, Bytes, TxHash, U256, bytes},
    providers::Provider,
    rpc::types::state::{AccountOverride, StateOverridesBuilder},
    sol_types::SolValue,
};
use futures_util::TryFutureExt;
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
    error::{EstimateFeeError, SendActionError, UpgradeAccountError, from_eyre_error},
    price::PriceOracle,
    signers::DynSigner,
    storage::{RelayStorage, StorageApi},
    transactions::{RelayTransaction, TransactionStatus},
    types::{
        Account, Action, Entry, FeeTokens, KeyType, KeyWith712Signer, PREPAccount, PartialAction,
        PartialUserOp, Quote, Signature, SignedQuote, UserOp,
        rpc::{
            AuthorizeKey, AuthorizeKeyResponse, BundleId, CallsStatus, CreateAccountParameters,
            CreateAccountResponse, CreateAccountResponseCapabilities, GetKeysParameters,
            PrepareCallsParameters, PrepareCallsResponse, PrepareCallsResponseCapabilities,
            PrepareUpgradeAccountParameters, SendPreparedCallsParameters,
            SendPreparedCallsResponse, UpgradeAccountParameters, UpgradeAccountResponse,
        },
    },
};

/// Ithaca `relay_` RPC namespace.
#[rpc(server, client, namespace = "relay")]
pub trait RelayApi {
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

    // todo: rewrite
    /// Send a sponsored transaction.
    ///
    /// The transaction will only be processed if:
    ///
    /// - The transaction is an [EIP-7702][eip-7702] transaction.
    /// - The transaction is an [EIP-1559][eip-1559] transaction to an EOA that is currently
    ///   delegated to one of the addresses above
    /// - The value in the transaction is exactly 0.
    ///
    /// The service will sign the transaction and inject it into the transaction pool, provided it
    /// is valid. The nonce is managed by the service.
    ///
    /// [eip-7702]: https://eips.ethereum.org/EIPS/eip-7702
    /// [eip-1559]: https://eips.ethereum.org/EIPS/eip-1559
    #[method(name = "sendAction", aliases = ["wallet_sendAction"])]
    async fn send_action(
        &self,
        request: Action,
        quote: SignedQuote,
        authorization: Option<SignedAuthorization>,
    ) -> RpcResult<TxHash>;

    /// Initialize an account.
    #[method(name = "createAccount", aliases = ["wallet_createAccount"])]
    async fn create_account(
        &self,
        parameters: CreateAccountParameters,
    ) -> RpcResult<CreateAccountResponse>;

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
}

#[async_trait]
impl RelayApiServer for Relay {
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
        let provider = self
            .inner
            .chains
            .get(request.chain_id)
            .ok_or(EstimateFeeError::UnsupportedChain(request.chain_id))?
            .provider;
        let Some(token) = self.inner.fee_tokens.find(request.chain_id, &token) else {
            return Err(EstimateFeeError::UnsupportedFeeToken(token).into());
        };

        // create key
        let mock_signer_address = self.inner.quote_signer.address();
        let key = KeyWith712Signer::random_admin(key_type)
            .and_then(|k| k.ok_or_else(|| EstimateFeeError::UnsupportedKeyType.into()))
            .map_err(EstimateFeeError::from)?;

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

        // fill userop
        let mut op = UserOp {
            eoa: request.op.eoa,
            executionData: request.op.executionData.clone(),
            nonce: request.op.nonce,
            paymentToken: token.address,
            // we intentionally do not use the maximum amount of gas since the contracts add a small
            // overhead when checking if there is sufficient gas for the op
            combinedGas: U256::from(100_000_000),
            initData: request.op.initData,
            ..Default::default()
        };

        // sign userop
        let signature = key
            .sign_typed_data(
                &op.as_eip712().map_err(|err| EstimateFeeError::InternalError(err.into()))?,
                &entrypoint
                    .eip712_domain(op.is_multichain())
                    .await
                    .map_err(EstimateFeeError::from)?,
            )
            .await
            .map_err(EstimateFeeError::InternalError)?;

        op.signature =
            Signature { innerSignature: signature, keyHash: key.key_hash(), prehash: false }
                .abi_encode_packed()
                .into();

        // we estimate gas and fees
        let (mut gas_estimate, native_fee_estimate) = futures_util::try_join!(
            entrypoint.simulate_execute(&op).map_err(EstimateFeeError::from),
            provider.estimate_eip1559_fees().map_err(EstimateFeeError::from)
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
            return Err(EstimateFeeError::UnavailablePrice(token.address).into());
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
            .map_err(|err| EstimateFeeError::InternalError(err.into()))?;

        Ok(quote.into_signed(sig))
    }

    async fn send_action(
        &self,
        request: Action,
        quote: SignedQuote,
        authorization: Option<SignedAuthorization>,
    ) -> RpcResult<TxHash> {
        let Chain { provider, transactions } = self
            .inner
            .chains
            .get(request.chain_id)
            .ok_or(EstimateFeeError::UnsupportedChain(request.chain_id))?;

        // check that the authorization item matches what's in the quote
        if quote.ty().authorization_address != authorization.as_ref().map(|auth| auth.address) {
            return Err(SendActionError::InvalidAuthItem {
                expected: quote.ty().authorization_address,
                got: authorization.map(|auth| auth.address),
            }
            .into());
        }

        if let Some(auth) = &authorization {
            // todo: persist auth
            if !auth.inner().chain_id().is_zero() {
                return Err(SendActionError::AuthItemNotChainAgnostic.into());
            }

            let expected_nonce = provider
                .get_transaction_count(request.op.eoa)
                .await
                .map_err(SendActionError::from)?;

            if expected_nonce != auth.nonce {
                return Err(SendActionError::AuthItemInvalidNonce {
                    expected: expected_nonce,
                    got: auth.nonce,
                }
                .into());
            }
        } else {
            let code = provider.get_code_at(request.op.eoa).await.map_err(SendActionError::from)?;

            if code.get(..3) != Some(&EIP7702_DELEGATION_DESIGNATOR[..])
                || code[..] == EIP7702_CLEARED_DELEGATION
            {
                return Err(SendActionError::EoaNotDelegated(request.op.eoa).into());
            }
        }

        // this can be done by just verifying the signature & userop hash against the rfq
        // ticket from `relay_estimateFee`'
        if !quote
            .recover_address()
            .is_ok_and(|address| address == self.inner.quote_signer.address())
        {
            return Err(SendActionError::InvalidQuoteSignature.into());
        }

        // if we do **not** get an error here, then the quote ttl must be in the past, which means
        // it is expired
        if SystemTime::now().duration_since(quote.ty().ttl).is_ok() {
            return Err(SendActionError::QuoteExpired.into());
        }

        let tx = RelayTransaction::new(quote, self.inner.entrypoint, authorization);
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
                TransactionStatus::Failed(err) => return Err(SendActionError::internal(err).into()),
            }
        }

        return Err(SendActionError::InternalError(eyre::eyre!("Transaction failed")).into());
    }

    async fn create_account(
        &self,
        request: CreateAccountParameters,
    ) -> RpcResult<CreateAccountResponse> {
        // Creating account should have at least one admin key.
        if !request.capabilities.authorize_keys.iter().any(|key| key.key.isSuperAdmin) {
            return Err(eyre::eyre!("Create account should have one key."))
                .map_err(from_eyre_error)?;
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

        // Store PREPAccount in storage
        let prep_account = PREPAccount::initialize(request.capabilities.delegation, init_calls);
        self.inner
            .storage
            .write_prep(&prep_account)
            .map_err(|err| from_eyre_error(err.into()))
            .await?;

        Ok(CreateAccountResponse {
            address: prep_account.address,
            capabilities: CreateAccountResponseCapabilities {
                authorize_keys: request
                    .capabilities
                    .authorize_keys
                    .into_iter()
                    .map(|key| key.into_response())
                    .collect::<Vec<_>>(),
                delegation: prep_account.signed_authorization.address,
            },
        })
    }

    async fn get_keys(&self, request: GetKeysParameters) -> RpcResult<Vec<AuthorizeKeyResponse>> {
        let account = Account::new(
            request.address,
            self.inner
                .chains
                .get(request.chain_id)
                .ok_or(EstimateFeeError::UnsupportedChain(request.chain_id))? // todo error handling
                .provider,
        );

        // Get all keys from account
        let keys = account.keys().await.map_err(EstimateFeeError::from)?; // todo error handling

        // Get all permissions from non admin keys
        let mut permissioned_keys = account
            .permissions(keys.iter().filter(|(_, key)| !key.isSuperAdmin).map(|(hash, _)| *hash))
            .await
            .map_err(EstimateFeeError::from)?; // todo error handling

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

    async fn prepare_calls(
        &self,
        request: PrepareCallsParameters,
    ) -> RpcResult<PrepareCallsResponse> {
        let provider = self
            .inner
            .chains
            .get(request.chain_id)
            .ok_or(EstimateFeeError::UnsupportedChain(request.chain_id))?
            .provider;

        // Generate all calls that will authorize keys and set their permissions
        let authorize_calls = request.capabilities.authorize_keys.iter().flat_map(|key| {
            let (authorize_call, permissions_calls) = key.clone().into_calls();
            std::iter::once(authorize_call).chain(permissions_calls)
        });

        // todo: fetch them from somewhere.
        let revoke_keys = Vec::new();

        // Merges authorize calls with requested ones.
        let all_calls = authorize_calls.chain(request.calls).collect::<Vec<_>>();

        // todo: obtain key with permissions from contracts using request.capabilities.meta.key_hash
        // todo: pass key with permissions to estimate_fee instead of keyType
        let key = KeyType::WebAuthnP256;

        // Find if the address is delegated or if we have a PREPAccount in storage that can use to
        // delegate.
        let maybe_prep = provider
            .get_code_at(request.from)
            .into_future()
            .map_err(SendActionError::from)
            .and_then(|code| async move {
                if code.get(..3) != Some(&EIP7702_DELEGATION_DESIGNATOR[..])
                    || code[..] == EIP7702_CLEARED_DELEGATION
                {
                    return self
                        .inner
                        .storage
                        .read_prep(&request.from)
                        .await
                        .map_err(|err| SendActionError::InternalError(err.into()))?
                        .ok_or_else(|| SendActionError::EoaNotDelegated(request.from))
                        .map(Some);
                }
                Ok(None)
            })
            .await?;

        // Call estimateFee to give us a quote with a complete userOp that the user can sign
        let quote = self
            .estimate_fee(
                PartialAction {
                    op: PartialUserOp {
                        eoa: request.from,
                        executionData: all_calls.abi_encode().into(),
                        nonce: request.capabilities.meta.nonce,
                        initData: maybe_prep
                            .as_ref()
                            .map(|acc| acc.init_data())
                            .unwrap_or_default(),
                    },
                    chain_id: request.chain_id,
                },
                request.capabilities.meta.fee_token,
                maybe_prep.as_ref().map(|acc| acc.signed_authorization.address),
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
            .map_err(from_eyre_error)?;

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
        let provider = self
            .inner
            .chains
            .get(request.chain_id)
            .ok_or(EstimateFeeError::UnsupportedChain(request.chain_id))?
            .provider;

        // Upgrading account should have at least one authorize admin key since
        // `wallet_prepareCalls` only accepts non-root keys.
        if !request.capabilities.authorize_keys.iter().any(|key| key.key.isSuperAdmin) {
            return Err(eyre::eyre!("Upgrade account should have one admin authorization key."))
                .map_err(from_eyre_error)?;
        }

        // Generate all calls that will authorize keys and set their permissions
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
                        executionData: calls.abi_encode().into(),
                        // todo: should probably not be 0 https://github.com/ithacaxyz/relay/issues/193
                        nonce: U256::ZERO,
                        initData: bytes!(""),
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
            .map_err(UpgradeAccountError::InternalError)?;

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
                .map(|opt| opt.map(|acc| acc.signed_authorization))
                .map_err(|err| from_eyre_error(err.into()))?
        };

        // Broadcast transaction with UserOp
        let tx_hash = self
            .send_action(
                Action { op: op.clone(), chain_id: request.context.ty().chain_id },
                request.context,
                authorization,
            )
            .await
            .inspect_err(|err| {
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
            return Err(UpgradeAccountError::InvalidAuthAddress {
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
            .send_action(
                Action { op: op.clone(), chain_id: request.context.ty().chain_id },
                request.context,
                Some(request.authorization),
            )
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
