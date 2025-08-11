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
    constants::ESCROW_SALT_LENGTH,
    error::{IntentError, StorageError},
    estimation::{FeeEngine, PricingContext, SimulationContracts, simulate_init, simulate_intent},
    provider::ProviderExt,
    signers::Eip712PayLoadSigner,
    transactions::interop::InteropBundle,
    types::{
        AssetDiffResponse, AssetMetadata, AssetType, Call, ChainAssetDiffs, Escrow, FeeTokens,
        FundSource, FundingIntentContext, GasEstimate, Health, IERC20, IEscrow, IntentKind,
        Intents, Key, KeyHash, KeyType, KeyWith712Signer, MULTICHAIN_NONCE_PREFIX, MerkleLeafInfo,
        Orchestrator, OrchestratorContract,
        OrchestratorContract::IntentExecuted,
        Quotes, SignedCall, SignedCalls, Token, Transfer, VersionedContracts,
        rpc::{
            AddressOrNative, Asset7811, AssetFilterItem, CallKey, CallReceipt, CallStatusCode,
            ChainCapabilities, ChainFees, GetAssetsParameters, GetAssetsResponse, Meta,
            PrepareCallsCapabilities, PrepareCallsContext, PrepareUpgradeAccountResponse,
            RelayCapabilities, SendPreparedCallsCapabilities, UpgradeAccountContext,
            UpgradeAccountDigests, ValidSignatureProof,
        },
    },
    version::RELAY_SHORT_VERSION,
};
use alloy::{
    consensus::{TxEip1559, TxEip7702},
    eips::{
        eip1559::Eip1559Estimation,
        eip7702::{SignedAuthorization, constants::EIP7702_DELEGATION_DESIGNATOR},
    },
    primitives::{Address, B256, BlockNumber, Bytes, ChainId, U256, aliases::B192, bytes},
    providers::{DynProvider, Provider, utils::EIP1559_FEE_ESTIMATION_PAST_BLOCKS},
    rlp::Encodable,
    rpc::types::{
        Authorization,
        state::{AccountOverride, StateOverridesBuilder},
    },
    sol_types::{SolCall, SolValue},
};
use futures_util::{TryFutureExt, future::try_join_all, join};
use itertools::Itertools;
use jsonrpsee::{
    core::{RpcResult, async_trait},
    proc_macros::rpc,
};
use opentelemetry::trace::SpanKind;
use std::{collections::HashMap, iter, sync::Arc, time::SystemTime};
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
        Account, CreatableAccount, FeeEstimationContext, Intent, PartialIntent, Quote, Signature,
        SignedQuotes,
        rpc::{
            AuthorizeKey, AuthorizeKeyResponse, BundleId, CallsStatus, CallsStatusCapabilities,
            GetKeysParameters, PrepareCallsParameters, PrepareCallsResponse,
            PrepareCallsResponseCapabilities, PrepareUpgradeAccountParameters,
            SendPreparedCallsParameters, SendPreparedCallsResponse, UpgradeAccountParameters,
            VerifySignatureParameters, VerifySignatureResponse,
        },
    },
};

/// Ithaca `relay_` RPC namespace.
#[rpc(server, client, namespace = "wallet")]
pub trait RelayApi {
    /// Checks the health of the relay and returns its version.
    #[method(name = "health", aliases = ["health"])]
    async fn health(&self) -> RpcResult<Health>;

    /// Get capabilities of the relay, which are different sets of configuration values.
    ///
    /// See also <https://github.com/ethereum/EIPs/blob/master/EIPS/eip-5792.md#wallet_getcapabilities>
    #[method(name = "getCapabilities")]
    async fn get_capabilities(&self, chains: Option<Vec<ChainId>>) -> RpcResult<RelayCapabilities>;

    /// Get all keys for an account.
    #[method(name = "getKeys")]
    async fn get_keys(&self, parameters: GetKeysParameters)
    -> RpcResult<Vec<AuthorizeKeyResponse>>;

    /// Get all assets for an account.
    #[method(name = "getAssets")]
    async fn get_assets(&self, parameters: GetAssetsParameters) -> RpcResult<GetAssetsResponse>;

    /// Prepares a call bundle for a user.
    #[method(name = "prepareCalls")]
    async fn prepare_calls(
        &self,
        parameters: PrepareCallsParameters,
    ) -> RpcResult<PrepareCallsResponse>;

    /// Prepares an EOA to be upgraded.
    #[method(name = "prepareUpgradeAccount")]
    async fn prepare_upgrade_account(
        &self,
        parameters: PrepareUpgradeAccountParameters,
    ) -> RpcResult<PrepareUpgradeAccountResponse>;

    /// Send a signed call bundle.
    #[method(name = "sendPreparedCalls")]
    async fn send_prepared_calls(
        &self,
        parameters: SendPreparedCallsParameters,
    ) -> RpcResult<SendPreparedCallsResponse>;

    /// Upgrade an account.
    #[method(name = "upgradeAccount")]
    async fn upgrade_account(&self, parameters: UpgradeAccountParameters) -> RpcResult<()>;

    /// Get the status of a call batch that was sent via `send_prepared_calls`.
    ///
    /// The identifier of the batch is the value returned from `send_prepared_calls`.
    #[method(name = "getCallsStatus")]
    async fn get_calls_status(&self, parameters: BundleId) -> RpcResult<CallsStatus>;

    /// Get the status of a call batch that was sent via `send_prepared_calls`.
    ///
    /// The identifier of the batch is the value returned from `send_prepared_calls`.
    #[method(name = "verifySignature")]
    async fn verify_signature(
        &self,
        parameters: VerifySignatureParameters,
    ) -> RpcResult<VerifySignatureResponse>;
}

/// Implementation of the Ithaca `relay_` namespace.
#[derive(Debug, Clone)]
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
        funder_signer: DynSigner,
        quote_config: QuoteConfig,
        price_oracle: PriceOracle,
        fee_tokens: Arc<FeeTokens>,
        fee_recipient: Address,
        storage: RelayStorage,
        asset_info: AssetInfoServiceHandle,
        priority_fee_percentile: f64,
        escrow_refund_threshold: u64,
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
            escrow_refund_threshold,
        };
        Self { inner: Arc::new(inner) }
    }

    /// Fetches the user's balance for a fee token.
    #[instrument(skip_all)]
    async fn get_fee_token_balance(
        &self,
        account: Address,
        chain_id: ChainId,
        fee_token: Address,
    ) -> Result<U256, RelayError> {
        Ok(self
            .get_assets(GetAssetsParameters {
                account,
                asset_filter: [(chain_id, vec![AssetFilterItem::fungible(fee_token.into())])]
                    .into(),
                ..Default::default()
            })
            .await
            .map_err(RelayError::internal)?
            .balance_on_chain(chain_id, fee_token.into()))
    }

    /// Builds a complete intent from partial user input with computed fields.
    ///
    /// This function takes a PartialIntent (user input) and fills in all the computed
    /// fields needed for a complete Intent that can be signed and executed.
    fn build_intent_to_sign(
        &self,
        partial_intent: PartialIntent,
        fee_token: &Token,
        delegation_implementation: Address,
        context: &FeeEstimationContext,
        combined_gas: U256,
    ) -> Intent {
        Intent {
            eoa: partial_intent.eoa,
            executionData: partial_intent.execution_data.clone(),
            nonce: partial_intent.nonce,
            payer: partial_intent.payer.unwrap_or_default(),
            paymentToken: fee_token.address,
            paymentRecipient: self.inner.fee_recipient,
            supportedAccountImplementation: delegation_implementation,
            encodedPreCalls: partial_intent
                .pre_calls
                .into_iter()
                .map(|pre_call| pre_call.abi_encode().into())
                .collect(),
            encodedFundTransfers: partial_intent
                .fund_transfers
                .into_iter()
                .map(|(token, amount)| Transfer { token, amount }.abi_encode().into())
                .collect(),
            isMultichain: !context.intent_kind.is_single(),
            combinedGas: combined_gas,
            ..Default::default()
        }
    }

    /// Returns the [`RelayCapabilities`] for the given chain ids.
    pub async fn get_capabilities(&self, chains: Vec<ChainId>) -> RpcResult<RelayCapabilities> {
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

    /// Estimates additional fees to be paid for a intent (e.g the current L1 DA fees).
    ///
    /// ## Opstack
    ///
    /// The fee is impacted by the L1 Base fee and the blob base fee.
    ///
    /// Returns fees in ETH.
    #[allow(dead_code)]
    #[instrument(skip_all)]
    async fn estimate_extra_fee(
        &self,
        chain: &Chain,
        intent: &Intent,
        auth: Option<SignedAuthorization>,
        fees: &Eip1559Estimation,
        gas_estimate: &GasEstimate,
    ) -> Result<U256, RelayError> {
        // Include the L1 DA fees if we're on an OP rollup.
        let fee = if chain.is_optimism {
            // we only need the unsigned RLP data here because `estimate_l1_fee` will account for
            // signature overhead.
            let mut buf = Vec::new();
            if let Some(auth) = auth {
                TxEip7702 {
                    chain_id: chain.chain_id,
                    // we use random nonce as we don't yet know which signer will broadcast the
                    // intent
                    nonce: rand::random(),
                    gas_limit: gas_estimate.tx,
                    max_fee_per_gas: fees.max_fee_per_gas,
                    max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
                    to: self.orchestrator(),
                    input: intent.encode_execute(),
                    authorization_list: vec![auth],
                    ..Default::default()
                }
                .encode(&mut buf);
            } else {
                TxEip1559 {
                    chain_id: chain.chain_id,
                    nonce: rand::random(),
                    gas_limit: gas_estimate.tx,
                    max_fee_per_gas: fees.max_fee_per_gas,
                    max_priority_fee_per_gas: fees.max_priority_fee_per_gas,
                    to: self.orchestrator().into(),
                    input: intent.encode_execute(),
                    ..Default::default()
                }
                .encode(&mut buf);
            }

            chain.provider.estimate_l1_fee(buf.into()).await?
        } else {
            U256::ZERO
        };

        Ok(fee)
    }

    #[instrument(skip_all)]
    async fn estimate_fee(
        &self,
        intent: PartialIntent,
        chain_id: ChainId,
        _prehash: bool,
        context: FeeEstimationContext,
    ) -> Result<(ChainAssetDiffs, Quote), RelayError> {
        // Validate chain and token
        let chain =
            self.inner.chains.get(chain_id).ok_or(RelayError::UnsupportedChain(chain_id))?;
        let token = self
            .inner
            .fee_tokens
            .find(chain_id, &context.fee_token)
            .ok_or(QuoteError::UnsupportedFeeToken(context.fee_token))?;
        let provider = chain.provider.clone();

        // Fetch the user's balance for the fee token
        let _fee_token_balance =
            self.get_fee_token_balance(intent.eoa, chain_id, context.fee_token).await?;
        // create key
        let _mock_key = KeyWith712Signer::random_admin(context.account_key.keyType)
            .map_err(RelayError::from)
            .and_then(|k| k.ok_or_else(|| RelayError::Keys(KeysError::UnsupportedKeyType)))?;
        // create a mock transaction signer
        let mock_from = Address::random();

        // Parallelize fetching of assets, fee history, and eth price as they are independent
        let (assets_response, fee_history, eth_price) = try_join!(
            // Fetch the user's balance for the fee token
            async {
                self.get_assets(GetAssetsParameters {
                    account: intent.eoa,
                    asset_filter: [(
                        chain_id,
                        vec![AssetFilterItem::fungible(context.fee_token.into())],
                    )]
                    .into(),
                    ..Default::default()
                })
                .await
                .map_err(RelayError::internal)
            },
            // Fetch chain fee history
            async {
                provider
                    .get_fee_history(
                        EIP1559_FEE_ESTIMATION_PAST_BLOCKS,
                        Default::default(),
                        &[self.inner.priority_fee_percentile],
                    )
                    .await
                    .map_err(RelayError::from)
            },
            // Fetch ETH price
            async {
                // TODO: only handles eth as native fee token
                Ok(self.inner.price_oracle.eth_price(token.kind).await)
            }
        )?;

        let fee_token_balance =
            assets_response.balance_on_chain(chain_id, context.fee_token.into());

        // Add 1 wei worth of the fee token to ensure the user always has enough to pass the call
        let new_fee_token_balance = fee_token_balance.saturating_add(U256::from(1));

        // mocking key storage for the eoa, and the balance for the mock signer
        let mut overrides = StateOverridesBuilder::with_capacity(2)
            // simulateV1Logs requires it, so the function can only be called under a testing
            // environment
            .append(mock_from, AccountOverride::default().with_balance(U256::MAX))
            .append(
                intent.eoa,
                AccountOverride::default()
                    // If the fee token is the native token, we override it
                    .with_balance_opt(context.fee_token.is_zero().then_some(new_fee_token_balance))
                    .with_state_diff(if context.key_slot_override {
                        context.account_key.storage_slots()
                    } else {
                        Default::default()
                    })
                    // we manually etch the 7702 designator since we do not have a signed auth item
                    .with_code_opt(context.stored_authorization.as_ref().map(|auth| {
                        Bytes::from(
                            [&EIP7702_DELEGATION_DESIGNATOR, auth.address.as_slice()].concat(),
                        )
                    })),
            )
            .extend(context.state_overrides.clone());

        // If the fee token is an ERC20, we do a balance override, merging it with the client
        // supplied balance override if necessary.
        if !context.fee_token.is_zero() {
            overrides = overrides.extend(
                context
                    .balance_overrides
                    .clone()
                    .modify_token(context.fee_token, |balance| {
                        balance.add_balance(intent.eoa, new_fee_token_balance);
                    })
                    .into_state_overrides(&provider)
                    .await?,
            );
        }

        let overrides = overrides.build();
        let account = Account::new(intent.eoa, &provider).with_overrides(overrides.clone());

        // Fetch orchestrator and delegation in parallel (fee_history and eth_price already fetched
        // above)
        let (orchestrator, delegation) = try_join!(
            // Fetch orchestrator from the account and ensure it is supported
            async {
                let orchestrator_addr = account.get_orchestrator().await?;
                if !self.is_supported_orchestrator(&orchestrator_addr) {
                    return Err(RelayError::UnsupportedOrchestrator(orchestrator_addr));
                }
                Ok(Orchestrator::new(orchestrator_addr, &provider).with_overrides(overrides))
            },
            // Fetch delegation from the account and ensure it is supported
            self.has_supported_delegation(&account).map_err(RelayError::from)
        )?;

        debug!(
            %chain_id,
            fee_token = ?token,
            ?fee_history,
            ?eth_price,
            "Got fee parameters"
        );

        // Create fee engine for fee calculation and quote creation
        let fee_engine =
            FeeEngine::new(self.inner.price_oracle.clone(), self.inner.quote_config.clone());

        // Build intent from partial intent for simulation
        let mut intent_to_sign = Intent {
            eoa: intent.eoa,
            executionData: intent.execution_data.clone(),
            nonce: intent.nonce,
            payer: intent.payer.unwrap_or_default(),
            paymentToken: token.address,
            paymentRecipient: self.inner.fee_recipient,
            supportedAccountImplementation: delegation,
            encodedPreCalls: intent
                .pre_calls
                .iter()
                .map(|pre_call| pre_call.abi_encode().into())
                .collect(),
            encodedFundTransfers: intent
                .fund_transfers
                .iter()
                .map(|(token, amount)| {
                    Transfer { token: *token, amount: *amount }.abi_encode().into()
                })
                .collect(),
            isMultichain: !context.intent_kind.is_single(),
            ..Default::default()
        };

        // Set payment amount for simulation
        intent_to_sign.set_legacy_payment_amount(U256::from(1));

        let contracts = SimulationContracts {
            simulator: self.simulator(),
            orchestrator: *orchestrator.address(),
            delegation_implementation: self.delegation_implementation(),
        };

        let simulation_response = simulate_intent(
            &provider,
            &intent_to_sign,
            context.clone(),
            fee_token_balance,
            contracts,
            self.inner.asset_info.clone(),
        )
        .await?;

        // Build final intent for pricing with gas estimate
        let mut intent_to_sign = self.build_intent_to_sign(
            intent,
            token,
            delegation,
            &context,
            simulation_response.gas_combined,
        );

        // Calculate intrinsic gas based on intent size
        let _intrinsic_gas = FeeEngine::calculate_intrinsic_cost(
            &OrchestratorContract::executeCall {
                encodedIntent: intent_to_sign.abi_encode().into(),
            }
            .abi_encode(),
            context.stored_authorization.is_some(),
        );

        let Some(eth_price) = eth_price else {
            return Err(RelayError::Quote(QuoteError::UnavailablePrice(token.address)));
        };
        // Use the gas estimate from the initial simulation
        let gas_estimate = GasEstimate::from_combined_gas(
            simulation_response.gas_combined.to(),
            simulation_response.intrinsic_gas,
            &self.inner.quote_config,
        );
        debug!(eoa = %intent_to_sign.eoa, gas_estimate = ?gas_estimate, "Estimated intent");

        // Fill combinedGas
        intent_to_sign.combinedGas = U256::from(gas_estimate.intent);

        // Set payment amount for quote calculation
        intent_to_sign.set_legacy_payment_amount(U256::from(1));

        // Fill empty dummy signature
        intent_to_sign.signature = bytes!("");
        intent_to_sign.funderSignature = bytes!("");

        // Calculate fees and generate quote using pre-fetched data
        let quote = fee_engine
            .calculate_fees(
                &provider,
                &chain,
                intent_to_sign,
                simulation_response.gas_combined,
                simulation_response.intrinsic_gas,
                PricingContext {
                    chain_id,
                    fee_token: token.clone(),
                    is_init: false,
                    fee_token_balance,
                    priority_fee_percentile: self.inner.priority_fee_percentile,
                },
                *orchestrator.address(),
                context.stored_authorization.as_ref().map(|auth| auth.address),
                fee_history,
                eth_price,
            )
            .await?;

        // Calculate fee token deficit and validate balance before proceeding
        let fee_token_deficit =
            quote.intent.totalPaymentMaxAmount.saturating_sub(fee_token_balance);

        // Update quote with fee token deficit (will be > 0 if user has insufficient balance)
        let mut final_quote = quote;
        final_quote.fee_token_deficit = fee_token_deficit;

        // Create ChainAssetDiffs with populated fiat values including fee
        let chain_asset_diffs = ChainAssetDiffs::new(
            simulation_response.asset_diffs,
            &final_quote,
            &self.inner.fee_tokens,
            &self.inner.price_oracle,
        )
        .await?;

        Ok((chain_asset_diffs, final_quote))
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
        let provider = self.provider(chain_id)?;

        let authorization_address = quote.authorization_address;
        let intent = &mut quote.intent;

        // Fill Intent with the fee payment signature (if exists).
        intent.paymentSignature = capabilities.fee_signature.clone();

        // Fill Intent with the user signature.
        intent.signature = signature;

        // Compute EIP-712 digest for the intent
        let (eip712_digest, _) = intent
            .compute_eip712_data(quote.orchestrator, &provider)
            .await
            .map_err(RelayError::from)?;

        // Sign fund transfers if any
        if !intent.encodedFundTransfers.is_empty() {
            // Set funder contract address and sign
            intent.funderSignature = self
                .inner
                .funder_signer
                .sign_payload_hash(eip712_digest)
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
                provider.get_transaction_count(quote.intent.eoa).await.map_err(RelayError::from)?;

            if expected_nonce != auth.nonce {
                return Err(AuthError::AuthItemInvalidNonce {
                    expected: expected_nonce,
                    got: auth.nonce,
                }
                .into());
            }
        } else {
            let account = Account::new(quote.intent.eoa, provider);
            // todo: same as above
            if !account.is_delegated().await? {
                return Err(AuthError::EoaNotDelegated(quote.intent.eoa).into());
            }
        }

        // set our payment recipient
        quote.intent.paymentRecipient = self.inner.fee_recipient;

        let tx = RelayTransaction::new(quote.clone(), authorization.clone(), eip712_digest);
        self.inner.storage.add_bundle_tx(bundle_id, tx.id).await?;

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
                if let RelayError::Auth(auth_err) = &err
                    && auth_err.is_eoa_not_delegated()
                    && let Some(account) = self.inner.storage.read_account(&request.address).await?
                {
                    return account.authorized_keys();
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
        let Some(stored) = self.inner.storage.read_account(&account.address()).await? else {
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
                            stored.signed_authorization.address().as_slice(),
                        ]
                        .concat(),
                    ),
                )
                .build(),
        );

        account.delegation_implementation().await?.ok_or_else(|| {
            RelayError::Auth(
                AuthError::InvalidDelegationProxy(*stored.signed_authorization.address()).boxed(),
            )
        })
    }

    /// Returns an iterator over all installed [`Chain`]s.
    pub fn chains(&self) -> impl Iterator<Item = &Chain> {
        self.inner.chains.chains()
    }

    /// Returns the chain [`DynProvider`].
    pub fn provider(&self, chain_id: ChainId) -> Result<DynProvider, RelayError> {
        Ok(self.inner.chains.get(chain_id).ok_or(RelayError::UnsupportedChain(chain_id))?.provider)
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

    /// Simulates the account initialization call.
    #[allow(dead_code)]
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
            PartialIntent {
                eoa: account.address,
                execution_data: Vec::<Call>::new().abi_encode().into(),
                nonce: U256::from_be_bytes(B256::random().into()) << 64,
                payer: None,
                pre_calls: vec![account.pre_call.clone()],
                fund_transfers: vec![],
            },
            chain_id,
            false,
            FeeEstimationContext {
                fee_token: Address::ZERO,
                stored_authorization: Some(account.signed_authorization.clone()),
                account_key: mock_key.key().clone(),
                key_slot_override: true,
                intent_kind: IntentKind::Single,
                state_overrides: Default::default(),
                balance_overrides: Default::default(),
            },
        )
        .await?;

        Ok(())
    }

    /// Builds a chain intent.
    async fn build_intent(
        &self,
        request: &PrepareCallsParameters,
        maybe_stored: Option<&CreatableAccount>,
        nonce: U256,
        intent_kind: IntentKind,
    ) -> Result<(ChainAssetDiffs, Quote), RelayError> {
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

        // We only apply client-supplied state overrides on intents on the destination chain
        let (state_overrides, balance_overrides) = match intent_kind {
            IntentKind::Single | IntentKind::MultiOutput { .. } => {
                (request.state_overrides.clone(), request.balance_overrides.clone())
            }
            _ => (Default::default(), Default::default()),
        };

        // Call estimateFee to give us a quote with a complete intent that the user can sign
        let (asset_diff, quote) = self
            .estimate_fee(
                PartialIntent {
                    eoa,
                    execution_data: request.calls.abi_encode().into(),
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
                request.chain_id,
                request_key.prehash,
                FeeEstimationContext {
                    fee_token: request.capabilities.meta.fee_token,
                    stored_authorization: maybe_stored
                        .as_ref()
                        .map(|acc| acc.signed_authorization.clone()),
                    account_key: key,
                    key_slot_override: false,
                    intent_kind,
                    state_overrides,
                    balance_overrides,
                },
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
        mut request: PrepareCallsParameters,
        intent_kind: Option<IntentKind>,
    ) -> RpcResult<PrepareCallsResponse> {
        // Checks calls and precall calls in the request
        request.check_calls(self.delegation_implementation())?;

        let provider = self.provider(request.chain_id)?;

        // Find if the address is delegated or if we have a stored account in storage that can use
        // to delegate.
        let mut maybe_stored = None;
        if let Some(from) = &request.from
            && !Account::new(*from, provider.clone()).is_delegated().await?
        {
            maybe_stored = Some(
                self.inner
                    .storage
                    .read_account(from)
                    .await
                    .map_err(|e| RelayError::InternalError(e.into()))?
                    .ok_or_else(|| RelayError::Auth(AuthError::EoaNotDelegated(*from).boxed()))?,
            );
        }

        // Generate all requested calls.
        request.calls = self.generate_calls(&request).await?;

        // Get next available nonce for DEFAULT_SEQUENCE_KEY
        let nonce = request.get_nonce(maybe_stored.as_ref(), &provider).await?;

        // If we're dealing with a PreCall do not estimate
        let (asset_diff, context) = if request.capabilities.pre_call {
            let precall = SignedCall {
                eoa: request.from.unwrap_or_default(),
                executionData: request.calls.abi_encode().into(),
                nonce,
                signature: Bytes::new(),
            };

            (AssetDiffResponse::default(), PrepareCallsContext::with_precall(precall))
        } else {
            let (asset_diffs, quotes) =
                self.build_quotes(&request, nonce, maybe_stored.as_ref(), intent_kind).await?;

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
            .compute_signing_digest(maybe_stored.as_ref(), self.orchestrator(), &provider)
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
        nonce: U256,
        maybe_stored: Option<&CreatableAccount>,
        intent_kind: Option<IntentKind>,
    ) -> RpcResult<(AssetDiffResponse, Quotes)> {
        // todo(onbjerg): this is incorrect. we still want to also do multichain if you do not have
        // enough funds to execute the intent, regardless of whether the user requested any funds
        // specifically. i'm too dumb to figure out the exact call graph of this right now, so will
        // leave this as an exercise for later.
        // Check if funding is required
        // todo: this only supports one asset...
        if let Some(required_funds) = request.capabilities.required_funds.first()
            && self.inner.chains.interop().is_some()
        {
            self.determine_quote_strategy(
                request,
                required_funds.address,
                required_funds.value,
                nonce,
                maybe_stored,
            )
            .await
        } else {
            self.build_single_chain_quote(request, maybe_stored, nonce, intent_kind)
                .await
                .map_err(Into::into)
        }
    }

    /// Generates a list of chain and amounts that fund a target chain operation.
    ///
    /// # Returns
    ///
    /// Returns `None` if there were not enough funds across all chains.
    ///
    /// Returns `Some(vec![])` if the destination chain does not require any funding from other
    /// chains.
    #[expect(clippy::too_many_arguments)]
    #[instrument(skip(self, request_key, assets))]
    async fn source_funds(
        &self,
        eoa: Address,
        request_key: &CallKey,
        assets: GetAssetsResponse,
        destination_chain_id: ChainId,
        requested_asset: AddressOrNative,
        amount: U256,
        total_leaves: usize,
    ) -> Result<Option<Vec<FundSource>>, RelayError> {
        let existing = assets.balance_on_chain(destination_chain_id, requested_asset);
        let mut remaining = amount.saturating_sub(existing);
        if remaining.is_zero() {
            return Ok(Some(vec![]));
        }

        // collect (chain, balance) for all other chains that have >0 balance
        let mut sources: Vec<(ChainId, Address, U256)> = assets
            .0
            .iter()
            .filter_map(|(&chain, assets)| {
                if chain == destination_chain_id {
                    return None;
                }

                let mapped = self
                    .inner
                    .fee_tokens
                    .map_interop_asset(destination_chain_id, requested_asset.address(), chain)?
                    .address;

                let balance = assets
                    .iter()
                    .find(|a| a.address.address() == mapped)
                    .map(|a| a.balance)
                    .unwrap_or(U256::ZERO);

                if balance.is_zero() { None } else { Some((chain, mapped, balance)) }
            })
            .collect();

        // highest balances first
        sources.sort_unstable_by(|a, b| b.2.cmp(&a.2));

        // todo(onbjerg): this is serial, so it can be pretty bad for performance for large
        // multichain intents. we *could* optimistically query multiple chains at a time, even if we
        // discard the result later
        let mut plan = Vec::new();
        for (chain, asset, balance) in sources {
            if remaining.is_zero() {
                break;
            }

            // we simulate escrowing the smallest unit of the asset to get a sense of the fees
            let funding_context = FundingIntentContext {
                eoa,
                chain_id: chain,
                asset: asset.into(),
                amount: U256::from(1),
                fee_token: asset,
                // note(onbjerg): it doesn't matter what the output intent digest is for simulation,
                // as long as it's not zero. otherwise, the gas costs will differ a lot.
                output_intent_digest: B256::with_last_byte(1),
                output_chain_id: destination_chain_id,
            };
            let escrow_cost = Box::pin(self.prepare_calls_inner(
                self.build_funding_intent(funding_context, request_key.clone())?,
                // note(onbjerg): its ok the leaf isnt correct here for simulation
                Some(IntentKind::MultiInput {
                    leaf_info: MerkleLeafInfo { total: total_leaves, index: 0 },
                    fee: None,
                }),
            ))
            .await
            .map_err(RelayError::internal)
            .inspect_err(|err| error!("Failed to simulate funding intent: {err:?}"))?
            .context
            .quote()
            .expect("should always be a quote")
            .ty()
            .fees()
            .map(|(_, cost)| cost)
            .unwrap_or_default();

            let take = remaining.min(balance.saturating_sub(escrow_cost));
            plan.push(FundSource {
                chain_id: chain,
                amount: take,
                address: asset,
                cost: escrow_cost,
            });
            remaining = remaining.saturating_sub(take);
        }

        if remaining.is_zero() {
            return Ok(Some(plan));
        }

        Ok(None)
    }

    /// Determine quote strategy based on asset availability across chains.
    ///
    /// The inner algorithm is as follows:
    ///
    /// - Simulate the intent for the destination chain as if it was a single chain intent.
    /// - If there are enough funds on the destination chain, return a single chain quote.
    /// - Otherwise, try to fund the destination chain with assets from other chains.
    /// - Since the output intent was simulated as a single chain intent, the fees are guaranteed to
    ///   be off, so we simulate it again as a multi-chain intent, with the funds we sourced.
    /// - Since simulating it as a multichain intent raises the fees, we need to source funds again;
    ///   we continue this process a number of times, until `balance + funding - required_assets -
    ///   fee >= 0`.
    #[instrument(skip(self, request, maybe_stored), fields(chain_id = request.chain_id))]
    async fn determine_quote_strategy(
        &self,
        request: &PrepareCallsParameters,
        requested_asset: Address,
        requested_funds: U256,
        nonce: U256,
        maybe_stored: Option<&CreatableAccount>,
    ) -> RpcResult<(AssetDiffResponse, Quotes)> {
        let eoa = request.from.ok_or(IntentError::MissingSender)?;
        let source_fee = request.capabilities.meta.fee_token == requested_asset;

        // Only query inventory, if funds have been requested in the target chain.
        let asset = if requested_asset.is_zero() {
            AddressOrNative::Native
        } else {
            AddressOrNative::Address(requested_asset)
        };

        // todo(onbjerg): let's restrict this further to just the tokens we care about
        let assets = self.get_assets(GetAssetsParameters::eoa(eoa)).await?;
        let requested_asset_balance_on_dst =
            assets.balance_on_chain(request.chain_id, requested_asset.into());

        // Simulate the output intent first to get the fees required to execute it.
        //
        // Note: We execute it as a multichain output, but without fund sources. The assumption here
        // is that the simulator will transfer the requested assets.
        let (_, quotes) = self
            .build_single_chain_quote(
                request,
                maybe_stored,
                nonce,
                Some(IntentKind::MultiOutput {
                    leaf_index: 1,
                    fund_transfers: vec![(
                        requested_asset,
                        // Deduct funds that already exist on the destination chain.
                        requested_funds.saturating_sub(requested_asset_balance_on_dst),
                    )],
                    settler_context: Vec::<ChainId>::new().abi_encode().into(),
                }),
            )
            .await?;
        // It should never happen that we do not have a quote from this simulation, but to avoid
        // outright crashing we just throw an internal error.
        let mut output_quote =
            quotes.quotes.into_iter().next().ok_or_else(|| {
                RelayError::InternalError(eyre::eyre!("no quote after simulation"))
            })?;

        // If we can cover the fees + requested assets *without* `sourced_funds`, then we can
        // just do this single chain instead.
        if requested_asset_balance_on_dst
            .checked_sub(requested_funds)
            .and_then(|n| {
                n.checked_sub(if source_fee {
                    output_quote.intent.totalPaymentMaxAmount
                } else {
                    U256::ZERO
                })
            })
            .is_some()
        {
            debug!(
                %eoa,
                chain_id = %request.chain_id,
                %requested_asset,
                %requested_funds,
                %requested_asset_balance_on_dst,
                %source_fee,
                fee = %output_quote.intent.totalPaymentMaxAmount,
                "Falling back to single chain for intent"
            );
            return self
                .build_single_chain_quote(request, maybe_stored, nonce, None)
                .await
                .map_err(Into::into);
        }

        // ensure interop has been configured, before proceeding
        self.inner.chains.interop().ok_or(QuoteError::MultichainDisabled)?;

        // ensure the requested asset is supported for interop
        if !self
            .inner
            .fee_tokens
            .find(request.chain_id, &requested_asset)
            .is_some_and(|t| t.interop)
        {
            return Err(RelayError::UnsupportedAsset {
                chain: request.chain_id,
                asset: requested_asset,
            }
            .into());
        }

        // We have to source funds from other chains. Since we estimated the output fees as if it
        // was a single chain intent, we now have to build an estimate the multichain intent to get
        // the true fees. After this, we do one more pass of finding funds on other chains.
        //
        // The issue here is that if we send even 1 unit too little of the fees required to execute
        // the output intent, it will revert because of us, and we won't be able to claim
        // the input funds, and we know for sure that validating a single chain intent !=
        // validating a multichain intent.
        //
        // Since the cost of validating a multichain intent is proportional to the size of the
        // merkle tree, we find funds in a loop until `balance + funds - required_assets - fee >=
        // 0`.
        //
        // We constrain this to three attempts.
        let mut num_funding_chains = 1;
        for _ in 0..3 {
            // Figure out what chains to pull funds from, if any. This will pull the funds the user
            // requested from chains, minus the cost of transferring those funds out of the
            // respective chains.
            debug!(
                %eoa,
                chain_id = %request.chain_id,
                %requested_asset,
                %requested_funds,
                %requested_asset_balance_on_dst,
                %source_fee,
                fee = %output_quote.intent.totalPaymentMaxAmount,
                "Trying to source funds"
            );
            let (sourced_funds, funding_chains) = if let Some(new_chains) = self
                .source_funds(
                    eoa,
                    request.key.as_ref().ok_or(IntentError::MissingKey)?,
                    assets.clone(),
                    request.chain_id,
                    asset,
                    requested_funds
                        + if source_fee {
                            output_quote.intent.totalPaymentMaxAmount
                        } else {
                            U256::ZERO
                        },
                    num_funding_chains + 1,
                )
                .await?
            {
                (new_chains.iter().map(|source| source.amount).sum(), new_chains)
            } else {
                return Err(RelayError::InsufficientFunds {
                    required: requested_funds,
                    chain_id: request.chain_id,
                    asset: requested_asset,
                }
                .into());
            };
            num_funding_chains = funding_chains.len();
            let input_chain_ids: Vec<ChainId> = funding_chains.iter().map(|s| s.chain_id).collect();
            let interop = self.inner.chains.interop().ok_or(QuoteError::MultichainDisabled)?;

            debug!(
                %eoa,
                chain_id = %request.chain_id,
                %requested_asset,
                %requested_funds,
                %requested_asset_balance_on_dst,
                %source_fee,
                fee = %output_quote.intent.totalPaymentMaxAmount,
                ?input_chain_ids,
                "Found potential fund sources"
            );

            // Encode the input chain IDs for the settler context
            let settler_context =
                interop.encode_settler_context(input_chain_ids).map_err(RelayError::from)?;

            // Simulate multi-chain
            let (output_asset_diffs, new_quote) = self
                .build_intent(
                    request,
                    maybe_stored,
                    nonce,
                    IntentKind::MultiOutput {
                        leaf_index: funding_chains.len(),
                        fund_transfers: vec![(requested_asset, sourced_funds)],
                        settler_context,
                    },
                )
                .await?;
            output_quote = new_quote;

            // If the existing balance on the destination chain, plus any funds we've sourced, minus
            // the requested amount of funds (and the fee if the requested asset is also the fee
            // token) is 0 or more, we're done.
            //
            // If `balance + sourced_funds - requested_funds - fee?` is `0`, then we've sourced
            // exactly the amount we need. If it's more, then we're overfunding a bit, which is not
            // the worst scenario, but ideally we get as close to 0 as possible.
            if requested_asset_balance_on_dst
                .saturating_add(sourced_funds)
                .checked_sub(requested_funds)
                .and_then(|n| {
                    n.checked_sub(if source_fee {
                        output_quote.intent.totalPaymentMaxAmount
                    } else {
                        U256::ZERO
                    })
                })
                .is_some()
            {
                // Compute EIP-712 digest (settlement_id)
                let (output_intent_digest, _) = output_quote
                    .intent
                    .compute_eip712_data(
                        output_quote.orchestrator,
                        &self.provider(request.chain_id)?,
                    )
                    .await
                    .map_err(RelayError::from)?;

                let request_key = request.key.as_ref().ok_or(IntentError::MissingKey)?;
                let funding_intents = try_join_all(funding_chains.iter().enumerate().map(
                    async |(leaf_index, source)| {
                        self.simulate_funding_intent(
                            eoa,
                            request_key.clone(),
                            MerkleLeafInfo { total: num_funding_chains + 1, index: leaf_index },
                            source,
                            output_intent_digest,
                            request.chain_id,
                        )
                        .await
                    },
                ))
                .await?;

                // Collect all quotes and build aggregated asset diff response
                let mut all_quotes = Vec::with_capacity(funding_intents.len() + 1);
                let mut all_asset_diffs = AssetDiffResponse::default();

                // Process source chains
                for resp in funding_intents {
                    all_quotes
                        .extend(resp.context.quote().expect("should exist").ty().quotes.clone());
                    all_asset_diffs.extend(resp.capabilities.asset_diff);
                }

                // Add output chain
                all_quotes.push(output_quote);
                all_asset_diffs.push(request.chain_id, output_asset_diffs);

                return Ok((
                    all_asset_diffs,
                    Quotes {
                        quotes: all_quotes,
                        ttl: SystemTime::now()
                            .checked_add(self.inner.quote_config.ttl)
                            .expect("should never overflow"),
                        // todo(onbjerg): a little silly that we have to set this to `None`, then
                        // call `with_merke_payload`. we should consider
                        // smth like Quotes::new(quotes, ttl).with_merkle_payload(..) or
                        // Quotes::multichain(quotes, ttl, root)
                        multi_chain_root: None,
                    }
                    .with_merkle_payload(
                        funding_chains
                            .iter()
                            .map(|source| source.chain_id)
                            .chain(iter::once(request.chain_id))
                            .map(|chain| self.provider(chain))
                            .collect::<Result<Vec<_>, _>>()?,
                    )
                    .await?,
                ));
            }
        }

        Err(RelayError::InternalError(eyre::eyre!(
            "exhausted max attempts at estimating multichain action"
        ))
        .into())
    }

    async fn simulate_funding_intent(
        &self,
        eoa: Address,
        request_key: CallKey,
        leaf_info: MerkleLeafInfo,
        source: &FundSource,
        output_intent_digest: B256,
        output_chain_id: ChainId,
    ) -> RpcResult<PrepareCallsResponse> {
        let funding_context = FundingIntentContext {
            eoa,
            chain_id: source.chain_id,
            asset: source.address.into(),
            amount: source.amount,
            fee_token: source.address,
            output_intent_digest,
            output_chain_id,
        };

        self.prepare_calls_inner(
            self.build_funding_intent(funding_context, request_key)?,
            Some(IntentKind::MultiInput {
                leaf_info,
                // we override the fees here to avoid re-estimating. if we
                // re-estimate, we might end up with
                // a higher fee, which will invalidate the entire call.
                fee: Some((source.address, source.cost)),
            }),
        )
        .await
    }

    /// Build a single-chain quote
    async fn build_single_chain_quote(
        &self,
        request: &PrepareCallsParameters,
        maybe_stored: Option<&CreatableAccount>,
        nonce: U256,
        intent_kind: Option<IntentKind>,
    ) -> Result<(AssetDiffResponse, Quotes), RelayError> {
        let (asset_diffs, quote) = self
            .build_intent(request, maybe_stored, nonce, intent_kind.unwrap_or(IntentKind::Single))
            .await?;

        Ok((
            AssetDiffResponse::new(request.chain_id, asset_diffs),
            Quotes {
                quotes: vec![quote],
                ttl: SystemTime::now()
                    .checked_add(self.inner.quote_config.ttl)
                    .expect("should never overflow"),
                multi_chain_root: None,
            },
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

        let interop = self.inner.chains.interop().ok_or(QuoteError::MultichainDisabled)?;
        interop.send_bundle(bundle).await?;

        Ok(bundle_id)
    }

    /// Creates a [`InteropBundle`] from signed quotes for multichain transactions.
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
                    self.provider(quote.chain_id)
                        .map(|provider| (quote.intent.clone(), provider, quote.orchestrator))
                })
                .collect::<Result<_, _>>()?,
        );

        // Create InteropBundle
        let interop = self.inner.chains.interop().ok_or(QuoteError::MultichainDisabled)?;
        let settler_id = interop.settler_id();
        let mut bundle = InteropBundle::new(bundle_id, settler_id);

        // last quote is the output intent
        let dst_idx = quotes.ty().quotes.len() - 1;

        let root = intents.root().await?;
        let tx_futures = quotes.ty().quotes.iter().enumerate().map(async |(idx, quote)| {
            let proof = intents.get_proof_immutable(idx)?;
            let merkle_sig = (proof, root, signature.clone()).abi_encode_params().into();

            self.prepare_tx(bundle_id, quote.clone(), capabilities.clone(), merkle_sig)
                .await
                .map(|tx| (idx, tx))
                .map_err(|e| RelayError::InternalError(e.into()))
        });

        // Append transactions directly to bundle
        for (idx, tx) in try_join_all(tx_futures).await? {
            if idx == dst_idx {
                bundle.append_dst(tx);
            } else {
                bundle.append_src(tx);
            }
        }

        Ok(bundle)
    }
}

#[async_trait]
impl RelayApiServer for Relay {
    async fn health(&self) -> RpcResult<Health> {
        let chains_ok = try_join_all(self.chains().map(|chain| async {
            chain.provider().get_block_number().await.inspect_err(|err| {
                error!(
                    %err,
                    chain_id=%chain.id(),
                    "Failed to obtain block number for health check",
                );
            })
        }))
        .await
        .is_ok();

        let db_ok = self
            .inner
            .storage
            .ping()
            .await
            .inspect_err(|err| {
                error!(
                    %err,
                    "Failed to ping database for health check",
                );
            })
            .is_ok();

        if chains_ok && db_ok {
            Ok(Health { status: "rpc ok".into(), version: RELAY_SHORT_VERSION.into() })
        } else {
            Err(RelayError::Unhealthy.into())
        }
    }

    async fn get_capabilities(&self, chains: Option<Vec<ChainId>>) -> RpcResult<RelayCapabilities> {
        let chains =
            chains.unwrap_or_else(|| self.inner.chains.chain_ids_iter().copied().collect());
        self.get_capabilities(chains).await
    }

    async fn get_keys(&self, request: GetKeysParameters) -> RpcResult<Vec<AuthorizeKeyResponse>> {
        Ok(self.get_keys(request).await?)
    }

    async fn get_assets(&self, mut request: GetAssetsParameters) -> RpcResult<GetAssetsResponse> {
        // If no explicit asset_filter was provided, build it from the other filters, the supported
        // chains and supported fee tokens
        if request.asset_filter.is_empty() {
            // If there is no chain filter provided, just use all chains that the relay supports.
            let chains = if request.chain_filter.is_empty() {
                self.inner.chains.chain_ids_iter().copied().collect()
            } else {
                request.chain_filter
            };

            for chain in chains {
                // If there is no asset type filter provided, just use all assets that the relay
                // supports on this chain.
                let mut items = vec![];

                if request.asset_type_filter.is_empty()
                    || request.asset_type_filter.contains(&AssetType::Native)
                {
                    items.push(AssetFilterItem {
                        address: AddressOrNative::Native,
                        asset_type: AssetType::Native,
                    });
                }

                if (request.asset_type_filter.is_empty()
                    || request.asset_type_filter.contains(&AssetType::ERC20))
                    && let Some(tokens) = self.inner.fee_tokens.chain_tokens(chain)
                {
                    for token in tokens {
                        if token.address == Address::ZERO {
                            continue;
                        }

                        items.push(AssetFilterItem {
                            address: AddressOrNative::Address(token.address),
                            asset_type: AssetType::ERC20,
                        });
                    }
                }

                request.asset_filter.insert(chain, items);
            }
        }

        let chain_details = request.asset_filter.iter().map(async |(chain, assets)| {
            let chain_provider = self.provider(*chain)?;

            let txs =
                assets.iter().filter(|asset| !asset.asset_type.is_erc721()).map(async |asset| {
                    if asset.asset_type.is_native() {
                        return Ok::<_, RelayError>(Asset7811 {
                            address: AddressOrNative::Native,
                            balance: chain_provider.get_balance(request.account).await?,
                            asset_type: asset.asset_type,
                            metadata: None,
                        });
                    }

                    let erc20 = IERC20::new(asset.address.address(), &chain_provider);

                    let (balance, decimals, name, symbol) = chain_provider
                        .multicall()
                        .add(erc20.balanceOf(request.account))
                        .add(erc20.decimals())
                        .add(erc20.name())
                        .add(erc20.symbol())
                        .aggregate()
                        .await?;

                    Ok(Asset7811 {
                        address: asset.address,
                        balance,
                        asset_type: asset.asset_type,
                        metadata: Some(AssetMetadata {
                            name: Some(name),
                            symbol: Some(symbol),
                            decimals: Some(decimals),
                            uri: None,
                        }),
                    })
                });
            Ok::<_, RelayError>((*chain, try_join_all(txs).await?))
        });

        Ok(GetAssetsResponse(try_join_all(chain_details).await?.into_iter().collect()))
    }

    async fn prepare_calls(
        &self,
        request: PrepareCallsParameters,
    ) -> RpcResult<PrepareCallsResponse> {
        self.prepare_calls_inner(request, None).await
    }

    async fn prepare_upgrade_account(
        &self,
        request: PrepareUpgradeAccountParameters,
    ) -> RpcResult<PrepareUpgradeAccountResponse> {
        let chain_id = request.chain_id.unwrap_or_else(|| {
            *self.inner.chains.chain_ids_iter().next().expect("there should be one")
        });
        let provider = self.provider(chain_id)?;

        // Upgrading account should have at least one authorize admin key since
        // `wallet_prepareCalls` only accepts non-root keys.
        if !request.capabilities.authorize_keys.iter().any(|key| key.key.isSuperAdmin) {
            return Err(KeysError::MissingAdminKey)?;
        }

        // Generate all calls that will authorize keys and set their permissions
        let calls = self.authorize_into_calls(request.capabilities.authorize_keys.clone())?;

        // Random sequence key, with a multichain prefix starting at nonce 0.
        let intent_nonce = (MULTICHAIN_NONCE_PREFIX << 240)
            | ((U256::from_be_bytes(B256::random().into()) >> 80) << 64);

        let pre_call = SignedCall {
            eoa: request.address,
            executionData: calls.abi_encode().into(),
            nonce: intent_nonce,
            signature: Bytes::new(),
        };

        let account =
            Account::new(request.address, &provider).with_delegation_override(&request.delegation);

        let (auth_nonce, _) = try_join!(
            async {
                provider
                    .get_transaction_count(request.address)
                    .pending()
                    .await
                    .map_err(RelayError::from)
            },
            self.ensure_latest_delegation(&account)
        )?;

        let authorization =
            Authorization { chain_id: U256::ZERO, address: request.delegation, nonce: auth_nonce };

        // Calculate the eip712 digest that the user will need to sign.
        let (pre_call_digest, typed_data) = pre_call
            .compute_eip712_data(self.orchestrator(), &provider)
            .await
            .map_err(RelayError::from)?;

        let digests =
            UpgradeAccountDigests { auth: authorization.signature_hash(), exec: pre_call_digest };

        let response = PrepareUpgradeAccountResponse {
            chain_id,
            context: UpgradeAccountContext {
                chain_id,
                address: request.address,
                authorization,
                pre_call,
            },
            digests,
            typed_data,
            capabilities: request.capabilities,
        };

        Ok(response)
    }

    async fn send_prepared_calls(
        &self,
        request: SendPreparedCallsParameters,
    ) -> RpcResult<SendPreparedCallsResponse> {
        let SendPreparedCallsParameters { capabilities, context, signature, key } = request;
        let Some(quotes) = context.take_quote() else {
            return Err(QuoteError::QuoteNotFound.into());
        };

        // broadcasts intents in transactions
        let bundle_id =
            self.send_intents(quotes, capabilities, signature, key).await.inspect_err(|err| {
                error!(
                    %err,
                    "Failed to submit call bundle transaction.",
                );
            })?;

        Ok(SendPreparedCallsResponse { id: bundle_id })
    }

    async fn upgrade_account(&self, request: UpgradeAccountParameters) -> RpcResult<()> {
        let UpgradeAccountParameters { context, signatures } = request;
        let provider = self.provider(context.chain_id)?;

        // Ensures precall authorizes an admin key
        if !context
            .pre_call
            .authorized_keys()
            .map_err(RelayError::from)?
            .iter()
            .any(|k| k.isSuperAdmin)
        {
            return Err(KeysError::MissingAdminKey)?;
        }

        // Ensures signature matches the requested account (7702 auth)
        let got = signatures
            .auth
            .recover_address_from_prehash(&context.authorization.signature_hash())
            .ok();
        if got != Some(context.address) {
            return Err(AuthError::InvalidAuthAddress { expected: context.address, got }.into());
        }

        let delegated_account = Account::new(context.address, &provider)
            .with_delegation_override(context.authorization.address());

        let mut storage_account = CreatableAccount::new(
            context.address,
            context.pre_call,
            context.authorization.into_signed(signatures.auth),
        );

        // Signed by the root eoa key.
        storage_account.pre_call.signature = signatures.exec.as_bytes().into();

        let (_, _, (pre_call_digest, _), expected_nonce) = try_join!(
            // Ensure it's using the lasted delegation implementation.
            self.ensure_latest_delegation(&delegated_account,),
            // Ensures the initialization precall is successful.
            simulate_init(
                &provider,
                &storage_account,
                context.chain_id,
                SimulationContracts {
                    simulator: self.simulator(),
                    orchestrator: self.orchestrator(),
                    delegation_implementation: self.delegation_implementation(),
                },
                self.inner.asset_info.clone(),
            ),
            // Calculate precall digest.
            async {
                storage_account
                    .pre_call
                    .compute_eip712_data(self.orchestrator(), &provider)
                    .await
                    .map_err(RelayError::from)
            },
            // Get account nonce.
            async {
                provider
                    .get_transaction_count(context.address)
                    .pending()
                    .await
                    .map_err(RelayError::from)
            },
        )?;

        // Ensures signature matches the requested account (precall)
        let got = signatures.exec.recover_address_from_prehash(&pre_call_digest).ok();
        if got != Some(context.address) {
            return Err(
                IntentError::InvalidPreCallRecovery { expected: context.address, got }.into()
            );
        }

        // Ensures authorization nonce matches the requested account
        if expected_nonce != storage_account.signed_authorization.nonce {
            return Err(AuthError::AuthItemInvalidNonce {
                expected: expected_nonce,
                got: storage_account.signed_authorization.nonce,
            }
            .into());
        }

        // Write to storage to be used on prepareCalls
        self.inner.storage.write_account(storage_account).await?;

        Ok(())
    }

    async fn get_calls_status(&self, id: BundleId) -> RpcResult<CallsStatus> {
        let tx_ids = self.inner.storage.get_bundle_transactions(id).await?;
        if tx_ids.is_empty() {
            return Err(StorageError::BundleDoesNotExist(id).into());
        }

        let tx_statuses =
            try_join_all(tx_ids.into_iter().map(|tx_id| async move {
                self.inner.storage.read_transaction_status(tx_id).await
            }))
            .await?;

        let any_pending = tx_statuses
            .iter()
            .any(|status| status.as_ref().is_none_or(|(_, status)| status.is_pending()));
        let any_failed = tx_statuses.iter().flatten().any(|(_, status)| status.is_failed());

        let receipts = tx_statuses
            .iter()
            .flatten()
            .filter_map(|(chain_id, status)| match status {
                TransactionStatus::Confirmed(receipt) => Some((*chain_id, receipt.clone())),
                _ => None,
            })
            .collect::<Vec<_>>();
        let block_numbers: HashMap<ChainId, BlockNumber> = HashMap::from_iter(
            try_join_all(receipts.iter().map(|(chain_id, _)| chain_id).unique().map(
                |chain_id| async move {
                    let provider = self.provider(*chain_id)?;
                    Ok::<_, RelayError>((*chain_id, provider.get_block_number().await?))
                },
            ))
            .await?
            .into_iter(),
        );
        let any_preconfs = receipts.iter().any(|(chain_id, receipt)| {
            receipt
                .block_number
                // SAFETY: we construct the hashmap using `receipts`, so there should never be a
                // block number missing here
                .is_some_and(|receipt_block| receipt_block > *block_numbers.get(chain_id).unwrap())
        });

        // note(onbjerg): this currently rests on the assumption that there is only one intent per
        // transaction, and that each transaction in a bundle originates from a single user
        //
        // in the future, this may not be the case, and we need to store the originating users
        // address in the txs table.
        //
        // note that we also assume that failure to decode a log as `IntentExecuted` means the
        // intent failed
        let any_reverted = receipts.iter().any(|(_, receipt)| {
            IntentExecuted::try_from_receipt(receipt).is_none_or(|e| e.has_error())
        });
        let all_reverted = receipts.iter().all(|(_, receipt)| {
            IntentExecuted::try_from_receipt(receipt).is_none_or(|e| e.has_error())
        });

        let status = if any_failed {
            CallStatusCode::Failed
        } else if any_pending {
            CallStatusCode::Pending
        } else if all_reverted {
            CallStatusCode::Reverted
        } else if any_reverted {
            CallStatusCode::PartiallyReverted
        } else if any_preconfs {
            CallStatusCode::PreConfirmed
        } else {
            CallStatusCode::Confirmed
        };

        let capabilities = if tx_statuses.len() > 1 {
            self.inner
                .storage
                .get_interop_status(id)
                .await?
                .map(|status| CallsStatusCapabilities { interop_status: Some(status) })
        } else {
            None
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
            capabilities,
        })
    }

    async fn verify_signature(
        &self,
        parameters: VerifySignatureParameters,
    ) -> RpcResult<VerifySignatureResponse> {
        let VerifySignatureParameters { address, digest, signature, chain_id } = parameters;

        let mut init_pre_call = None;
        let mut account = Account::new(address, self.provider(chain_id)?);
        let signatures: Vec<Signature> = self
            .get_keys(GetKeysParameters { address, chain_id })
            .await?
            .into_iter()
            .filter_map(|k| {
                k.authorize_key.key.isSuperAdmin.then_some(Signature {
                    innerSignature: signature.clone(),
                    keyHash: k.authorize_key.key.key_hash(),
                    prehash: false,
                })
            })
            .collect();

        if !account.is_delegated().await? {
            let Some(stored) = self.inner.storage.read_account(&address).await? else {
                return Err(StorageError::AccountDoesNotExist(address).into());
            };

            account = account.with_overrides(
                StateOverridesBuilder::with_capacity(1)
                    .append(
                        stored.address,
                        AccountOverride::default()
                            .with_code(Bytes::from(
                                [
                                    &EIP7702_DELEGATION_DESIGNATOR,
                                    stored.signed_authorization.address.as_slice(),
                                ]
                                .concat(),
                            ))
                            .with_state_diff(
                                stored
                                    .authorized_keys()?
                                    .into_iter()
                                    .flat_map(|k| k.authorize_key.key.storage_slots().into_iter()),
                            ),
                    )
                    .build(),
            );

            init_pre_call = Some(stored.pre_call);
        }

        let results = try_join_all(
            signatures.into_iter().map(|signature| account.validate_signature(digest, signature)),
        )
        .await
        .map_err(RelayError::from)?;

        let key_hash = results.into_iter().find_map(|result| result);

        let proof = key_hash.map(|key_hash| ValidSignatureProof {
            account: account.address(),
            key_hash,
            init_pre_call,
        });

        return Ok(VerifySignatureResponse { valid: proof.is_some(), proof });
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
    fee_tokens: Arc<FeeTokens>,
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
    /// Escrow refund threshold in seconds
    escrow_refund_threshold: u64,
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

    /// The simulator address.
    pub fn simulator(&self) -> Address {
        self.inner.contracts.simulator.address
    }

    /// The escrow address.
    pub fn escrow(&self) -> Address {
        self.inner.contracts.escrow.address
    }

    /// Creates an escrow struct for funding intents.
    fn create_escrow_struct(&self, context: &FundingIntentContext) -> Result<Escrow, RelayError> {
        let salt = B192::random().as_slice()[..ESCROW_SALT_LENGTH].try_into().map_err(|_| {
            RelayError::InternalError(eyre::eyre!("Failed to create salt from B192"))
        })?;

        // Calculate refund timestamp
        let current_timestamp = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(RelayError::internal)?
            .as_secs();
        let refund_timestamp =
            U256::from(current_timestamp.saturating_add(self.inner.escrow_refund_threshold));

        Ok(Escrow {
            salt,
            depositor: context.eoa,
            recipient: self.inner.contracts.funder.address,
            token: context.asset.address(),
            settler: self
                .inner
                .chains
                .interop()
                .ok_or(QuoteError::MultichainDisabled)?
                .settler_address(),
            sender: self.orchestrator(),
            settlementId: context.output_intent_digest,
            senderChainId: U256::from(context.output_chain_id),
            escrowAmount: context.amount,
            refundAmount: context.amount,
            refundTimestamp: refund_timestamp,
        })
    }

    /// Builds the escrow calls based on the asset type.
    ///
    /// IMPORTANT: The escrow call is always placed last in the returned vector.
    /// This ordering is critical as it's relied upon by other parts of the system
    /// (e.g., extract_escrow_details) for efficient parsing.
    fn build_escrow_calls(&self, escrow: Escrow, context: &FundingIntentContext) -> Vec<Call> {
        let escrow_call = Call {
            to: self.inner.contracts.escrow.address,
            value: if context.asset.is_native() { context.amount } else { U256::ZERO },
            data: IEscrow::escrowCall { _escrows: vec![escrow] }.abi_encode().into(),
        };

        // Build the transaction calls based on token type
        if context.asset.is_native() {
            // Native token: escrow call only (which is also the last call)
            vec![escrow_call]
        } else {
            // ERC20 token: approve then escrow (escrow is last)
            vec![
                Call {
                    to: context.asset.address(),
                    value: U256::ZERO,
                    data: IERC20::approveCall {
                        spender: self.inner.contracts.escrow.address,
                        amount: context.amount,
                    }
                    .abi_encode()
                    .into(),
                },
                escrow_call,
            ]
        }
    }

    /// Builds a funding intent for multichain operations.
    ///
    /// Creates the necessary calls to escrow funds on an input chain that will
    /// be used to fund a multichain intent execution on the output chain.
    ///
    /// Note: The escrow call is always placed last in the call sequence. This is
    /// relied upon by the extract_escrow_details method for efficient parsing.
    fn build_funding_intent(
        &self,
        context: FundingIntentContext,
        request_key: CallKey,
    ) -> Result<PrepareCallsParameters, RelayError> {
        let escrow = self.create_escrow_struct(&context)?;
        let calls = self.build_escrow_calls(escrow, &context);

        Ok(PrepareCallsParameters {
            calls,
            chain_id: context.chain_id,
            from: Some(context.eoa),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: context.fee_token, nonce: None },
                revoke_keys: vec![],
                pre_calls: vec![],
                pre_call: false,
                required_funds: vec![],
            },
            state_overrides: Default::default(),
            balance_overrides: Default::default(),
            key: Some(request_key),
        })
    }
}
