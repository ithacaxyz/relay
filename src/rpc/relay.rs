//! # Ithaca Relay RPC
//!
//! Implementations of a custom `relay_` namespace.

use crate::{
    asset::AssetInfoServiceHandle,
    constants::{COLD_SSTORE_GAS_BUFFER, ESCROW_SALT_LENGTH, P256_GAS_BUFFER},
    error::{IntentError, StorageError},
    estimation::{build_simulation_overrides, fees::approx_intrinsic_cost},
    provider::ProviderExt,
    signers::Eip712PayLoadSigner,
    transactions::interop::InteropBundle,
    types::{
        Asset, AssetDiffResponse, AssetMetadataWithPrice, AssetPrice, AssetType, Call,
        ChainAssetDiffs, DelegationStatus, Escrow, FundSource, FundingIntentContext, GasEstimate,
        Health, IERC20, IEscrow, IntentKind, Intents, Key, KeyHash, KeyType,
        MULTICHAIN_NONCE_PREFIX, MerkleLeafInfo,
        OrchestratorContract::IntentExecuted,
        Quotes, SignedCall, SignedCalls, Transfer, VersionedContracts,
        VersionedOrchestratorContracts,
        rpc::{
            AddFaucetFundsParameters, AddFaucetFundsResponse, AddressOrNative, Asset7811,
            AssetFilterItem, CallKey, CallReceipt, CallStatusCode, ChainCapabilities,
            ChainFeeToken, ChainFees, GetAssetsParameters, GetAssetsResponse,
            GetAuthorizationParameters, GetAuthorizationResponse, Meta, PrepareCallsCapabilities,
            PrepareCallsContext, PrepareUpgradeAccountResponse, RelayCapabilities,
            SendPreparedCallsCapabilities, UpgradeAccountContext, UpgradeAccountDigests,
            ValidSignatureProof,
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
    primitives::{
        Address, B256, BlockNumber, Bytes, ChainId, TxKind, U64, U256, aliases::B192, bytes,
    },
    providers::{DynProvider, Provider, utils::EIP1559_FEE_ESTIMATION_PAST_BLOCKS},
    rlp::Encodable,
    rpc::types::{
        Authorization, TransactionRequest,
        state::{AccountOverride, StateOverridesBuilder},
    },
    sol_types::{SolCall, SolValue},
};
use alloy_chains::NamedChain;
use futures::{StreamExt, stream::FuturesOrdered};
use futures_util::{future::try_join_all, join};
use itertools::Itertools;
use jsonrpsee::{
    core::{RpcResult, async_trait},
    proc_macros::rpc,
};
use opentelemetry::trace::SpanKind;
use std::{collections::HashMap, iter, sync::Arc, time::SystemTime};
use tokio::try_join;
use tracing::{Instrument, Level, debug, error, info, instrument, span, warn};

use crate::{
    chains::{Chain, Chains},
    config::QuoteConfig,
    error::{AuthError, KeysError, QuoteError, RelayError},
    price::PriceOracle,
    signers::DynSigner,
    storage::{RelayStorage, StorageApi},
    transactions::{RelayTransaction, TransactionStatus},
    types::{
        Account, CreatableAccount, FeeEstimationContext, Intent, KeyWith712Signer, Orchestrator,
        PartialIntent, Quote, Signature, SignedQuotes,
        rpc::{
            AuthorizeKey, AuthorizeKeyResponse, BundleId, CallsStatus, CallsStatusCapabilities,
            GetKeysParameters, GetKeysResponse, PrepareCallsParameters, PrepareCallsResponse,
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
    async fn get_capabilities(&self, chains: Option<Vec<U64>>) -> RpcResult<RelayCapabilities>;

    /// Get all keys for an account.
    #[method(name = "getKeys")]
    async fn get_keys(&self, parameters: GetKeysParameters) -> RpcResult<GetKeysResponse>;

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

    /// Get the authorization and initialization data for an account that is intended to be
    /// delegated.
    #[method(name = "getAuthorization")]
    async fn get_authorization(
        &self,
        parameters: GetAuthorizationParameters,
    ) -> RpcResult<GetAuthorizationResponse>;

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

    /// Add faucet funds to an address on a specific chain.
    #[method(name = "addFaucetFunds")]
    async fn add_faucet_funds(
        &self,
        parameters: AddFaucetFundsParameters,
    ) -> RpcResult<AddFaucetFundsResponse>;
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
        chains: Arc<Chains>,
        quote_signer: DynSigner,
        funder_signer: DynSigner,
        quote_config: QuoteConfig,
        price_oracle: PriceOracle,
        fee_recipient: Address,
        storage: RelayStorage,
        asset_info: AssetInfoServiceHandle,
        escrow_refund_threshold: u64,
    ) -> Self {
        let inner = RelayInner {
            contracts,
            chains,
            fee_recipient,
            quote_signer,
            funder_signer,
            quote_config,
            price_oracle,
            storage,
            asset_info,
            escrow_refund_threshold,
        };
        Self { inner: Arc::new(inner) }
    }

    /// Returns the [`RelayCapabilities`] for the given chain ids.
    pub async fn get_capabilities(&self, chains: Vec<ChainId>) -> RpcResult<RelayCapabilities> {
        let capabilities = try_join_all(chains.into_iter().filter_map(|chain_id| {
            // Relay needs a chain endpoint to support a chain.
            let chain = self.inner.chains.get(chain_id)?;
            let provider = chain.provider().clone();
            let native_uid = chain.assets().native()?.0.clone();
            let fee_tokens = chain.assets().fee_tokens();

            Some(async move {
                let fee_tokens = try_join_all(fee_tokens.into_iter().map(|(token_uid, token)| {
                    let provider = provider.clone();
                    let native_uid = native_uid.clone();
                    async move {
                        let rate = self
                            .inner
                            .price_oracle
                            .native_conversion_rate(token_uid.clone(), native_uid)
                            .await
                            .ok_or(QuoteError::UnavailablePrice(token.address))?;
                        let symbol = self
                            .inner
                            .asset_info
                            .get_asset_info_list(
                                &provider,
                                vec![Asset::infer_from_address(token.address)],
                            )
                            .await
                            .ok()
                            .and_then(|map| {
                                map.iter()
                                    .next()
                                    .and_then(|(_, asset)| asset.metadata.symbol.clone())
                            });
                        Ok(ChainFeeToken::new(token_uid, token, symbol, Some(rate)))
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
    #[instrument(skip_all)]
    async fn estimate_extra_fee(
        &self,
        chain: &Chain,
        intent: &Intent,
        auth: Option<SignedAuthorization>,
        fees: &Eip1559Estimation,
        gas_estimate: &GasEstimate,
    ) -> Result<U256, RelayError> {
        // Include the L1 DA fees if we're on an OP or Arbitrum rollup.
        let fee = if chain.is_optimism() {
            // we only need the unsigned RLP data here because `estimate_l1_fee` will account for
            // signature overhead.
            let mut buf = Vec::new();
            if let Some(auth) = auth {
                TxEip7702 {
                    chain_id: chain.id(),
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
                    chain_id: chain.id(),
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

            chain.provider().estimate_l1_op_fee(buf.into()).await?
        } else if chain.is_arbitrum() {
            chain
                .provider()
                .estimate_l1_arb_fee(
                    chain.id(),
                    self.orchestrator(),
                    gas_estimate.tx,
                    *fees,
                    auth,
                    intent.encode_execute(),
                )
                .await?
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
        prehash: bool,
        context: FeeEstimationContext,
    ) -> Result<(ChainAssetDiffs, Quote), RelayError> {
        let chain = self.inner.chains.ensure_chain(chain_id)?;

        let provider = chain.provider().clone();
        let (native_uid, _) =
            chain.assets().native().ok_or(RelayError::UnsupportedChain(chain_id))?;
        let (token_uid, token) = chain
            .assets()
            .find_by_address(context.fee_token)
            .ok_or(QuoteError::UnsupportedFeeToken(context.fee_token))
            .inspect_err(|_| {
                let supported_fee_tokens: Vec<_> =
                    chain.assets().fee_tokens().into_iter().map(|(_, desc)| desc.address).collect();
                warn!(
                    %chain_id,
                    fee_token = %context.fee_token,
                    supported = ?supported_fee_tokens,
                    "unsupported fee token supplied"
                );
            })?;

        // create key
        let mock_key = KeyWith712Signer::random_admin(context.account_key.keyType)
            .map_err(RelayError::from)
            .and_then(|k| k.ok_or_else(|| RelayError::Keys(KeysError::UnsupportedKeyType)))?;
        // create a mock transaction signer
        let mock_from = Address::random();

        // Parallelize fetching of assets, fee history, and eth price as they are independent
        let (assets_response, fee_history, eth_price) = try_join!(
            // Fetch the user's balance for the fee token
            async {
                self.get_assets(GetAssetsParameters::for_asset_on_chain(
                    intent.eoa,
                    chain_id,
                    context.fee_token,
                ))
                .await
                .map_err(RelayError::internal)
            },
            // Fetch chain fee history
            async {
                provider
                    .get_fee_history(
                        EIP1559_FEE_ESTIMATION_PAST_BLOCKS,
                        Default::default(),
                        &[chain.fee_config().priority_fee_percentile],
                    )
                    .await
                    .map_err(RelayError::from)
            },
            // Fetch native asset price
            async {
                Ok(self
                    .inner
                    .price_oracle
                    .native_conversion_rate(token_uid.clone(), native_uid.clone())
                    .await)
            }
        )?;

        let fee_token_balance =
            assets_response.balance_on_chain(chain_id, context.fee_token.into());

        // Build state overrides for simulation
        let overrides =
            build_simulation_overrides(&intent, &context, mock_from, fee_token_balance, &provider)
                .await?
                .build();
        let account = Account::new(intent.eoa, &provider).with_overrides(overrides.clone());

        let orchestrator =
            self.get_supported_orchestrator(&account, &provider).await?.with_overrides(overrides);

        debug!(
            %chain_id,
            fee_token = ?token,
            ?fee_history,
            ?eth_price,
            orchestrator_version = ?orchestrator.version(),
            "Got fee parameters"
        );

        let native_fee_estimate = chain.fee_config().estimate_eip1559_fees(&fee_history);

        let Some(eth_price) = eth_price else {
            return Err(QuoteError::UnavailablePrice(token.address).into());
        };
        let payment_per_gas = (native_fee_estimate.max_fee_per_gas as f64
            * 10u128.pow(token.decimals as u32) as f64)
            / f64::from(eth_price);

        // fill intent - use the appropriate version based on orchestrator
        let mut intent_to_sign = Intent::for_orchestrator(
            orchestrator.version().expect("orchestrator version should be set"),
        )
        .with_eoa(intent.eoa)
        .with_execution_data(intent.execution_data.clone())
        .with_nonce(intent.nonce)
        .with_payer(intent.payer.unwrap_or_default())
        .with_payment_token(token.address)
        .with_payment_recipient(self.inner.fee_recipient)
        .with_supported_account_implementation(intent.delegation_implementation)
        .with_encoded_pre_calls(
            intent.pre_calls.into_iter().map(|pre_call| pre_call.abi_encode().into()).collect(),
        )
        .with_encoded_fund_transfers(
            intent
                .fund_transfers
                .into_iter()
                .map(|(token, amount)| Transfer { token, amount }.abi_encode().into())
                .collect(),
        );

        // For multichain intents, set the interop flag
        if !context.intent_kind.is_single() {
            intent_to_sign = intent_to_sign.with_interop();
        }

        // For MultiOutput intents, set the settler address and context
        if let IntentKind::MultiOutput { settler_context, .. } = &context.intent_kind {
            self.inner.chains.interop().ok_or(QuoteError::MultichainDisabled)?;
            intent_to_sign = intent_to_sign
                .with_settler(self.inner.chains.settler_address(chain.id())?)
                .with_settler_context(settler_context.clone());
        }

        if intent_to_sign.is_interop() {
            // For multichain intents, add a mocked merkle signature
            intent_to_sign = intent_to_sign
                .with_mock_merkle_signature(
                    &context.intent_kind,
                    *orchestrator.address(),
                    &provider,
                    &mock_key,
                    context.account_key.key_hash(),
                    prehash,
                )
                .await
                .map_err(RelayError::from)?;
        } else {
            // For single chain intents, sign the intent directly
            let signature = mock_key
                .sign_payload_hash(
                    intent_to_sign
                        .compute_eip712_data(*orchestrator.address(), &provider)
                        .await
                        .map_err(RelayError::from)?
                        .0,
                )
                .await
                .map_err(RelayError::from)?;

            intent_to_sign = intent_to_sign.with_signature(
                Signature {
                    innerSignature: signature,
                    keyHash: context.account_key.key_hash(),
                    prehash,
                }
                .abi_encode_packed()
                .into(),
            );
        }

        if !intent_to_sign.encoded_fund_transfers().is_empty() {
            intent_to_sign = intent_to_sign.with_funder(self.inner.contracts.funder.address);
        }

        let gas_validation_offset =
            // Account for gas variation in P256 sig verification.
            if context.account_key.keyType.is_secp256k1() { U256::ZERO } else { P256_GAS_BUFFER }
                // Account for the case when we change zero fee token balance to non-zero, thus skipping a cold storage write
                // We're adding 1 wei to the balance in build_simulation_overrides, so it will be non-zero if fee_token_balance is zero
                + if fee_token_balance.is_zero() && !context.fee_token.is_zero() {
                    COLD_SSTORE_GAS_BUFFER
                } else {
                    U256::ZERO
                };

        // For simulation purposes we only simulate with a payment of 1 unit of the fee token. This
        // should be enough to simulate the gas cost of paying for the intent for most (if not all)
        // ERC20s.
        //
        // Additionally, we included a balance override of `balance + 1` unit of the fee token,
        // which ensures the simulation never reverts. Whether the user can actually really
        // pay for the intent execution or not is determined later and communicated to the
        // client.
        intent_to_sign.set_payment(U256::from(1));

        let (asset_diffs, sim_result) = orchestrator
            .simulate_execute(
                mock_from,
                self.get_simulator_for_orchestrator(*orchestrator.address()),
                &intent_to_sign,
                self.inner.asset_info.clone(),
                gas_validation_offset,
                chain.sim_mode(),
            )
            .await?;

        let intrinsic_gas = approx_intrinsic_cost(
            &intent_to_sign.encode_execute(),
            context.stored_authorization.is_some(),
        );

        let gas_estimate = GasEstimate::from_combined_gas(
            sim_result.gCombined.to(),
            intrinsic_gas,
            &self.inner.quote_config,
        );
        debug!(eoa = %intent.eoa, gas_estimate = ?gas_estimate, "Estimated intent");

        // Fill combinedGas
        intent_to_sign = intent_to_sign.with_combined_gas(U256::from(gas_estimate.intent));
        // Calculate the real fee
        let extra_fee_native = self
            .estimate_extra_fee(
                &chain,
                &intent_to_sign,
                context.stored_authorization.clone(),
                &native_fee_estimate,
                &gas_estimate,
            )
            .await?;

        let extra_payment =
            extra_fee_native * U256::from(10u128.pow(token.decimals as u32)) / eth_price;

        debug!(
            chain_id = %chain.id(),
            %extra_payment,
            %extra_fee_native,
            %eth_price,
            "Calculated extra payment"
        );

        // Fill empty dummy signature
        intent_to_sign =
            intent_to_sign.with_signature(bytes!("")).with_funder_signature(bytes!(""));

        // Fill payment information
        //
        // If the fee has already been specified (multichain inputs only), we only simulate to get
        // asset diffs. Otherwise, we simulate to get the fee.
        let payment_amount = context.intent_kind.multi_input_fee().unwrap_or(
            extra_payment + U256::from((payment_per_gas * gas_estimate.tx as f64).ceil()),
        );
        intent_to_sign.set_payment(payment_amount);

        let fee_token_deficit =
            intent_to_sign.total_payment_max_amount().saturating_sub(fee_token_balance);
        let quote = Quote {
            chain_id,
            payment_token_decimals: token.decimals,
            intent: intent_to_sign,
            extra_payment,
            eth_price,
            tx_gas: gas_estimate.tx,
            native_fee_estimate,
            authorization_address: context.stored_authorization.as_ref().map(|auth| auth.address),
            orchestrator: *orchestrator.address(),
            fee_token_deficit,
        };

        // Create ChainAssetDiffs with populated fiat values including fee
        let chain_asset_diffs =
            ChainAssetDiffs::new(asset_diffs, &quote, &self.inner.chains, &self.inner.price_oracle)
                .await?;

        Ok((chain_asset_diffs, quote))
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

        // Fill Intent with the fee payment signature (if exists).
        quote.intent = quote
            .intent
            .with_payment_signature(capabilities.fee_signature.clone())
            .with_signature(signature);

        // Compute EIP-712 digest for the intent
        let (eip712_digest, _) = quote
            .intent
            .compute_eip712_data(quote.orchestrator, &provider)
            .await
            .map_err(RelayError::from)?;

        // Sign fund transfers if any
        if !quote.intent.encoded_fund_transfers().is_empty() {
            // Set funder contract address and sign
            quote.intent = quote
                .intent
                .with_funder_signature(
                    self.inner
                        .funder_signer
                        .sign_payload_hash(eip712_digest)
                        .await
                        .map_err(RelayError::from)?,
                )
                .with_funder(self.inner.contracts.funder.address);
        }

        // Set non-eip712 payment fields. Since they are not included into the signature so we
        // need to enforce it here.
        let payment_amount = quote.intent.pre_payment_max_amount();
        quote.intent.set_payment(payment_amount);

        // If there's an authorization address in the quote, we need to fetch the signed one
        // from storage.
        // todo: we should probably fetch this before sending any tx
        let authorization = if authorization_address.is_some() {
            self.inner
                .storage
                .read_account(quote.intent.eoa())
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

            let expected_nonce = provider
                .get_transaction_count(*quote.intent.eoa())
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
            let account = Account::new(*quote.intent.eoa(), provider);
            // todo: same as above
            if !account.is_delegated().await? {
                return Err(AuthError::EoaNotDelegated(*quote.intent.eoa()).into());
            }
        }

        // set our payment recipient
        quote.intent = quote.intent.with_payment_recipient(self.inner.fee_recipient);

        let tx = RelayTransaction::new(quote, authorization.clone(), eip712_digest);
        self.inner.storage.add_bundle_tx(bundle_id, tx.id).await?;

        Ok(tx)
    }

    /// Get keys from an account across multiple chains.
    #[instrument(skip_all)]
    async fn get_keys(&self, request: GetKeysParameters) -> Result<GetKeysResponse, RelayError> {
        // If chains specified, ensure they are supported,
        // if any are not supported, return an error,
        // if no chains specified, use all supported chains
        let chains = if request.chain_ids.is_empty() {
            self.inner.chains.chain_ids_iter().copied().collect()
        } else {
            for &chain_id in &request.chain_ids {
                self.inner.chains.ensure_chain(chain_id)?;
            }
            request.chain_ids.clone()
        };

        // Query keys from all requested chains in parallel and bubble errors
        let address = request.address;
        let pairs = try_join_all(chains.into_iter().map(|chain_id| async move {
            Ok::<_, RelayError>((chain_id, self.get_keys_for_chain(address, chain_id).await?))
        }))
        .await?;

        // Build response from successful results
        Ok(pairs.into_iter().map(|(chain_id, keys)| (U64::from(chain_id), keys)).collect())
    }

    /// Get keys from an account on a specific chain.
    #[instrument(skip_all)]
    async fn get_keys_for_chain(
        &self,
        address: Address,
        chain_id: ChainId,
    ) -> Result<Vec<AuthorizeKeyResponse>, RelayError> {
        match self.get_keys_onchain_single(address, chain_id).await {
            Ok(keys) => Ok(keys),
            Err(err) => {
                // We check our storage, since it might have been called after createAccount, but
                // before its onchain commit.
                if let RelayError::Auth(auth_err) = &err
                    && auth_err.is_eoa_not_delegated()
                    && let Some(account) = self.inner.storage.read_account(&address).await?
                {
                    return account.authorized_keys();
                }
                Err(err)
            }
        }
    }

    /// Get keys from an account onchain for a specific chain.
    #[instrument(skip_all)]
    async fn get_keys_onchain_single(
        &self,
        address: Address,
        chain_id: ChainId,
    ) -> Result<Vec<AuthorizeKeyResponse>, RelayError> {
        let account = Account::new(address, self.provider(chain_id)?);

        let (is_delegated, keys) = join!(account.is_delegated(), account.keys());

        if !is_delegated? {
            return Err(AuthError::EoaNotDelegated(address).boxed().into());
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

    /// Returns an iterator over all installed [`Chain`]s.
    pub fn chains(&self) -> impl Iterator<Item = &Chain> {
        self.inner.chains.chains_iter()
    }

    /// Returns the chain [`DynProvider`].
    pub fn provider(&self, chain_id: ChainId) -> Result<DynProvider, RelayError> {
        Ok(self.inner.chains.ensure_chain(chain_id)?.provider().clone())
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
    #[instrument(skip_all)]
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

        // Get keys for the specific chain (treat errors as no keys available)
        let keys = self.get_keys_for_chain(from, chain_id).await?;
        let key = keys.iter().find(|k| k.hash == key_hash).map(|k| k.authorize_key.key.clone());

        Ok(key)
    }

    /// Generates all calls from a [`PrepareCallsParameters`].
    fn generate_calls(&self, request: &PrepareCallsParameters) -> Result<Vec<Call>, RelayError> {
        // Generate all calls that will authorize  keys and set their permissions
        let authorize_calls =
            self.authorize_into_calls(request.capabilities.authorize_keys.clone())?;

        // Generate all revoke key calls
        let revoke_calls =
            request.capabilities.revoke_keys.iter().flat_map(|key| key.clone().into_calls());

        // Merges all previously generated calls.
        Ok(authorize_calls.into_iter().chain(request.calls.clone()).chain(revoke_calls).collect())
    }

    /// Returns the orchestrator if it's supported, otherwise returns an error.
    async fn get_supported_orchestrator<P: Provider + Clone>(
        &self,
        account: &Account<P>,
        provider: P,
    ) -> Result<Orchestrator<P>, RelayError> {
        let address = account.get_orchestrator().await?;

        // Get the version for the orchestrator
        let version = if self.orchestrator() == address {
            tracing::trace!(
                orchestrator = %address,
                version = ?self.inner.contracts.orchestrator.version,
                "Using current orchestrator"
            );
            self.inner.contracts.orchestrator.version.clone()
        } else if let Some(legacy) = self.get_legacy_orchestrator(address) {
            tracing::trace!(
                orchestrator = %address,
                version = ?legacy.orchestrator.version,
                "Using legacy orchestrator"
            );
            legacy.orchestrator.version.clone()
        } else {
            return Err(RelayError::UnsupportedOrchestrator(address));
        };

        Ok(Orchestrator::new(address, provider).with_version(version))
    }

    /// Checks if a delegation implementation needs upgrading.
    ///
    /// Returns Some(new_impl) if upgrade needed, None if current.
    /// Returns error if delegation is neither current nor legacy (unsupported).
    fn maybe_delegation_upgrade(
        &self,
        current_implementation: Address,
    ) -> Result<Option<Address>, RelayError> {
        let current = self.delegation_implementation();

        // Check if it's the current implementation (up to date)
        if current_implementation == current {
            return Ok(None);
        }

        // Check if it's a legacy implementation (needs upgrade)
        if self.legacy_delegations().any(|c| c == current_implementation) {
            return Ok(Some(current));
        }

        // It's neither current nor legacy - this is an error
        Err(AuthError::InvalidDelegation(current_implementation).into())
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

        // Get the delegation implementation from the stored authorization
        let delegation_impl = Account::new(account.address, self.provider(chain_id)?)
            .with_delegation_override(account.signed_authorization.address())
            .delegation_implementation()
            .await?
            .ok_or_else(|| {
                RelayError::Auth(
                    AuthError::InvalidDelegationProxy(*account.signed_authorization.address())
                        .boxed(),
                )
            })?;

        // Ensures that initialization precall works
        self.estimate_fee(
            PartialIntent {
                eoa: account.address,
                execution_data: Vec::<Call>::new().abi_encode().into(),
                nonce: U256::from_be_bytes(B256::random().into()) << 64,
                payer: None,
                pre_calls: vec![account.pre_call.clone()],
                fund_transfers: vec![],
                delegation_implementation: delegation_impl,
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
    #[instrument(skip_all)]
    async fn build_intent(
        &self,
        request: &PrepareCallsParameters,
        delegation_status: &DelegationStatus,
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
                    pre_calls: delegation_status
                        .stored_account()
                        .iter()
                        .map(|acc| acc.pre_call.clone())
                        .chain(request.capabilities.pre_calls.clone())
                        .collect(),
                    fund_transfers: intent_kind.fund_transfers(),
                    delegation_implementation: delegation_status.try_implementation()?,
                },
                request.chain_id,
                request_key.prehash,
                FeeEstimationContext {
                    fee_token: request.capabilities.meta.fee_token,
                    stored_authorization: delegation_status
                        .stored_account()
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

    #[instrument(skip_all)]
    async fn prepare_calls_inner(
        &self,
        mut request: PrepareCallsParameters,
        intent_kind: Option<IntentKind>,
    ) -> RpcResult<PrepareCallsResponse> {
        // Checks calls and precall calls in the request
        request.check_calls(self.delegation_implementation())?;

        let provider = self.provider(request.chain_id)?;

        // Get delegation status if there's a sender
        let delegation_status = if let Some(from) = request.from {
            Some(Account::new(from, provider.clone()).delegation_status(&self.inner.storage).await?)
        } else {
            None
        };

        // Generate all requested calls.
        request.calls = self.generate_calls(&request)?;

        // Check if upgrade is needed (only for non-precalls with a delegated account)
        if !request.capabilities.pre_call
            && let Some(status) = &delegation_status
            && let Ok(impl_addr) = status.try_implementation()
            && let Some(new_impl) = self.maybe_delegation_upgrade(impl_addr)?
        {
            request.calls.push(Call::upgrade_proxy_account(new_impl));
        }

        // Get next available nonce for DEFAULT_SEQUENCE_KEY
        let nonce = request
            .get_nonce(delegation_status.as_ref().and_then(|s| s.stored_account()), &provider)
            .await?;

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
            // Regular flow - sender and delegation status are required
            let Some(ref delegation_status) = delegation_status else {
                // delegation_status is None, only if we haven't received a from in the parameters
                return Err(IntentError::MissingSender.into());
            };

            let (asset_diffs, quotes) =
                self.build_quotes(&request, nonce, delegation_status, intent_kind).await?;

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
            .compute_signing_digest(
                delegation_status.as_ref().and_then(|s| s.stored_account()),
                self.orchestrator(),
                &provider,
            )
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
    #[instrument(skip_all)]
    async fn build_quotes(
        &self,
        request: &PrepareCallsParameters,
        nonce: U256,
        delegation_status: &DelegationStatus,
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
            && self.inner.chains.interop_asset(request.chain_id, required_funds.address).is_some()
        {
            self.determine_quote_strategy(
                request,
                required_funds.address,
                required_funds.value,
                nonce,
                delegation_status,
            )
            .await
        } else {
            self.build_single_chain_quote(request, delegation_status, nonce, intent_kind)
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
                    .chains
                    .map_interop_asset(destination_chain_id, chain, requested_asset.address())?
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

        // Simulate funding intents in parallel, preserving the order
        let mut funding_intents = sources
            .into_iter()
            .map(|(chain, asset, balance)| async move {
                // we simulate escrowing the smallest unit of the asset to get a sense of the fees
                let funding_context = FundingIntentContext {
                    eoa,
                    chain_id: chain,
                    asset: asset.into(),
                    amount: U256::from(1),
                    fee_token: asset,
                    // note(onbjerg): it doesn't matter what the output intent digest is for
                    // simulation, as long as it's not zero. otherwise, the gas
                    // costs will differ a lot.
                    output_intent_digest: B256::with_last_byte(1),
                    output_chain_id: destination_chain_id,
                };
                let escrow_cost = self
                    .prepare_calls_inner(
                        self.build_funding_intent(funding_context, request_key.clone())?,
                        // note(onbjerg): its ok the leaf isnt correct here for simulation
                        Some(IntentKind::MultiInput {
                            leaf_info: MerkleLeafInfo { total: total_leaves, index: 0 },
                            fee: None,
                        }),
                    )
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

                Result::<_, RelayError>::Ok((chain, asset, balance, escrow_cost))
            })
            .collect::<FuturesOrdered<_>>();

        let mut plan = Vec::new();
        while let Some((chain, asset, balance, escrow_cost)) =
            funding_intents.next().await.transpose()?
        {
            if remaining.is_zero() {
                break;
            }

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
    #[instrument(skip(self, request, delegation_status), fields(chain_id = request.chain_id))]
    async fn determine_quote_strategy(
        &self,
        request: &PrepareCallsParameters,
        requested_asset: Address,
        requested_funds: U256,
        nonce: U256,
        delegation_status: &DelegationStatus,
    ) -> RpcResult<(AssetDiffResponse, Quotes)> {
        let eoa = request.from.ok_or(IntentError::MissingSender)?;
        let source_fee = request.capabilities.meta.fee_token == requested_asset;

        // Only query inventory, if funds have been requested in the target chain.
        let asset = if requested_asset.is_zero() {
            AddressOrNative::Native
        } else {
            AddressOrNative::Address(requested_asset)
        };

        // Fetch all EOA assets (needed for source_funds) and funder's specific asset on destination
        // chain
        //
        // todo(onbjerg): let's restrict this further to just the tokens we care about
        let (assets, funder_assets) = try_join!(
            self.get_assets(GetAssetsParameters::eoa(eoa)),
            self.get_assets(GetAssetsParameters::for_asset_on_chain(
                self.inner.contracts.funder.address,
                request.chain_id,
                requested_asset
            ))
        )?;
        let requested_asset_balance_on_dst =
            assets.balance_on_chain(request.chain_id, requested_asset.into());

        let funder_balance_on_dst =
            funder_assets.balance_on_chain(request.chain_id, requested_asset.into());

        // Check if funder has sufficient liquidity for the requested asset
        let needed_funds = requested_funds.saturating_sub(requested_asset_balance_on_dst);
        if funder_balance_on_dst < needed_funds {
            return Err(QuoteError::InsufficientLiquidity.into());
        }

        // Simulate the output intent first to get the fees required to execute it.
        //
        // Note: We execute it as a multichain output, but without fund sources. The assumption here
        // is that the simulator will transfer the requested assets.
        let (_, quotes) = self
            .build_single_chain_quote(
                request,
                delegation_status,
                nonce,
                Some(IntentKind::MultiOutput {
                    leaf_index: 1,
                    fund_transfers: vec![(requested_asset, needed_funds)],
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
                    output_quote.intent.total_payment_max_amount()
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
                fee = %output_quote.intent.total_payment_max_amount(),
                "Falling back to single chain for intent"
            );
            return self
                .build_single_chain_quote(request, delegation_status, nonce, None)
                .await
                .map_err(Into::into);
        }

        // ensure interop has been configured, before proceeding
        self.inner.chains.interop().ok_or(QuoteError::MultichainDisabled)?;

        // ensure the requested asset is supported for interop
        self.inner.chains.interop_asset(request.chain_id, requested_asset).ok_or(
            RelayError::UnsupportedAsset { chain: request.chain_id, asset: requested_asset },
        )?;

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
                fee = %output_quote.intent.total_payment_max_amount(),
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
                            output_quote.intent.total_payment_max_amount()
                        } else {
                            U256::ZERO
                        },
                    num_funding_chains + 1,
                )
                .await?
            {
                (new_chains.iter().map(|source| source.amount).sum(), new_chains)
            } else {
                // We don't have enough funds across all chains, so we revert back to single chain
                // to produce a quote with a `feeTokenDeficit`.
                //
                // A more robust solution here is returning a `Result<Vec<FundSource>, Deficit>`
                // where the error specifies how much we have across all chains, and
                // we use that to produce the deficit, as the single chain
                // `feeTokenDeficit` is a bit misleading.
                return self
                    .build_single_chain_quote(request, delegation_status, nonce, None)
                    .await
                    .map_err(Into::into);
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
                fee = %output_quote.intent.total_payment_max_amount(),
                ?input_chain_ids,
                "Found potential fund sources"
            );

            // Encode the input chain IDs for the settler context
            let settler_context =
                interop.encode_settler_context(input_chain_ids).map_err(RelayError::from)?;

            // `sourced_funds` now also includes fees, so make sure the funder has enough balance to
            // transfer.
            if funder_balance_on_dst < sourced_funds {
                return Err(QuoteError::InsufficientLiquidity.into());
            }

            // Simulate multi-chain
            let (output_asset_diffs, new_quote) = self
                .build_intent(
                    request,
                    delegation_status,
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
                        output_quote.intent.total_payment_max_amount()
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

    #[instrument(skip_all)]
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
    #[instrument(skip_all)]
    async fn build_single_chain_quote(
        &self,
        request: &PrepareCallsParameters,
        delegation_status: &DelegationStatus,
        nonce: U256,
        intent_kind: Option<IntentKind>,
    ) -> Result<(AssetDiffResponse, Quotes), RelayError> {
        let (asset_diffs, quote) = self
            .build_intent(
                request,
                delegation_status,
                nonce,
                intent_kind.unwrap_or(IntentKind::Single),
            )
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
            .ensure_chain(tx.chain_id())?
            .transactions()
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

    /// Gets the token price for an asset, only returns a price if it's a fee token and the inner
    /// price fetch is successful
    async fn get_token_price(&self, chain: u64, asset: &AssetFilterItem) -> Option<AssetPrice> {
        let (uid, _) = self.inner.chains.fee_token(chain, asset.address.address())?;
        self.inner.price_oracle.usd_price(uid.clone()).await.map(AssetPrice::from_price)
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

    async fn get_capabilities(&self, chains: Option<Vec<U64>>) -> RpcResult<RelayCapabilities> {
        let chains = chains
            .map(|vec| vec.into_iter().map(|id| id.to::<u64>()).collect())
            .unwrap_or_else(|| self.inner.chains.chain_ids_iter().copied().collect());
        self.get_capabilities(chains).await
    }

    async fn get_keys(&self, request: GetKeysParameters) -> RpcResult<GetKeysResponse> {
        Ok(self.get_keys(request).await?)
    }

    #[instrument(skip_all)]
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
                    && let Some(tokens) = self.inner.chains.fee_tokens(chain)
                {
                    for (_, token) in tokens {
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

        let chain_details = request.asset_filter.into_iter().map(async |(chain, assets)| {
            let chain_provider = self.provider(chain)?;

            let txs =
                assets.iter().filter(|asset| !asset.asset_type.is_erc721()).map(async |asset| {
                    // get price if this is a fee token
                    let price = self.get_token_price(chain, asset).await;

                    if asset.asset_type.is_native() {
                        let symbol = NamedChain::try_from(chain)
                            .ok()
                            .and_then(|c| c.native_currency_symbol())
                            .map(ToString::to_string);

                        return Ok::<_, RelayError>(Asset7811 {
                            address: AddressOrNative::Native,
                            balance: chain_provider.get_balance(request.account).await?,
                            asset_type: asset.asset_type,
                            metadata: Some(AssetMetadataWithPrice {
                                name: None,
                                symbol,
                                // use a constant 18 for native assets
                                decimals: Some(18),
                                uri: None,
                                price,
                            }),
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
                        metadata: Some(AssetMetadataWithPrice {
                            name: Some(name),
                            symbol: Some(symbol),
                            decimals: Some(decimals),
                            uri: None,
                            price,
                        }),
                    })
                });
            Ok::<_, RelayError>((chain, try_join_all(txs).await?))
        });

        Ok(GetAssetsResponse(try_join_all(chain_details).await?.into_iter().collect()))
    }

    async fn prepare_calls(
        &self,
        request: PrepareCallsParameters,
    ) -> RpcResult<PrepareCallsResponse> {
        tracing::Span::current().record("eth.chain_id", request.chain_id);
        self.prepare_calls_inner(request, None).await
    }

    async fn prepare_upgrade_account(
        &self,
        request: PrepareUpgradeAccountParameters,
    ) -> RpcResult<PrepareUpgradeAccountResponse> {
        let chain_id = request.chain_id.unwrap_or_else(|| {
            *self.inner.chains.chain_ids_iter().next().expect("there should be one")
        });
        tracing::Span::current().record("eth.chain_id", chain_id);

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

        let auth_nonce = provider
            .get_transaction_count(request.address)
            .pending()
            .await
            .map_err(RelayError::from)?;

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
        tracing::Span::current().record("eth.chain_id", context.chain_id);

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

        let auth_address = *context.authorization.address();
        let delegated_account =
            Account::new(context.address, &provider).with_delegation_override(&auth_address);

        let mut storage_account = CreatableAccount::new(
            context.address,
            context.pre_call,
            context.authorization.into_signed(signatures.auth),
        );

        // Signed by the root eoa key.
        storage_account.pre_call =
            storage_account.pre_call.with_signature(signatures.exec.as_bytes().into());

        // Check the delegation implementation
        let impl_addr = delegated_account
            .delegation_implementation()
            .await?
            .ok_or(AuthError::InvalidDelegation(auth_address))?;

        if impl_addr != self.delegation_implementation() {
            return Err(AuthError::InvalidDelegation(impl_addr).into());
        }

        let (_, (pre_call_digest, _), expected_nonce) = try_join!(
            // Ensures the initialization precall is successful.
            self.simulate_init(&storage_account, context.chain_id),
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

    async fn get_authorization(
        &self,
        parameters: GetAuthorizationParameters,
    ) -> RpcResult<GetAuthorizationResponse> {
        let GetAuthorizationParameters { address } = parameters;

        let account = self
            .inner
            .storage
            .read_account(&address)
            .await
            .map_err(|e| RelayError::InternalError(e.into()))?
            .ok_or_else(|| StorageError::AccountDoesNotExist(address))?;

        Ok(GetAuthorizationResponse {
            authorization: account.signed_authorization.clone(),
            data: account.pre_call.executionData,
        })
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
        tracing::Span::current().record("eth.chain_id", chain_id);

        let mut init_pre_call = None;
        let mut account = Account::new(address, self.provider(chain_id)?);
        // Get keys for the specific chain (treat errors as no keys available)
        let keys = self.get_keys_for_chain(address, chain_id).await?;
        let signatures: Vec<Signature> = keys
            .iter()
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

    async fn add_faucet_funds(
        &self,
        parameters: AddFaucetFundsParameters,
    ) -> RpcResult<AddFaucetFundsResponse> {
        let AddFaucetFundsParameters { token_address, address, chain_id, value } = parameters;
        tracing::Span::current().record("eth.chain_id", chain_id);

        info!(
            "Processing faucet request for {} on chain {} with amount {}",
            address, chain_id, value
        );

        let chain =
            self.inner.chains.get(chain_id).ok_or(RelayError::UnsupportedChain(chain_id))?;

        // Disallow faucet usage on mainnet chains
        if alloy_chains::Chain::from(chain_id).named().is_some_and(|c| !c.is_testnet()) {
            warn!("Faucet request blocked on mainnet (chain {chain_id})");
            return Ok(AddFaucetFundsResponse {
                transaction_hash: None,
                message: Some("Faucet disabled on mainnet".to_string()),
            });
        }

        // Token must be a configured fee token on this chain
        let fee_tokens = chain.assets().fee_tokens();
        if !fee_tokens.iter().any(|(_, d)| d.address == token_address) {
            error!("Token address {} not supported for chain {}", token_address, chain_id);
            return Ok(AddFaucetFundsResponse {
                transaction_hash: None,
                message: Some("Token address not supported".to_string()),
            });
        }

        // Build calldata for mint(recipient, value)
        let calldata: Bytes = IERC20::mintCall { recipient: address, value }.abi_encode().into();

        // Estimate gas; if it fails, treat as not supported (e.g., token lacks mint or requires
        // role)
        let gas_limit = match chain
            .provider()
            .estimate_gas(
                TransactionRequest::default().to(token_address).input(calldata.clone().into()),
            )
            .await
        {
            Ok(g) => g,
            Err(e) => {
                error!(
                    "Faucet mint not supported for token {token_address} on chain {chain_id}: {e}"
                );
                return Ok(AddFaucetFundsResponse {
                    transaction_hash: None,
                    message: Some("Token address not supported".to_string()),
                });
            }
        };

        // Build internal transaction; TransactionService will pick an active relay signer
        let relay_tx = RelayTransaction::new_internal(
            TxKind::Call(token_address),
            calldata,
            chain.id(),
            gas_limit,
        );

        // Send and wait for confirmation
        let handle = chain.transactions().clone();
        let _ = handle.send_transaction(relay_tx.clone()).await.map_err(RelayError::from)?;
        let status = handle.wait_for_tx(relay_tx.id).await.map_err(|_| {
            RelayError::InternalError(eyre::eyre!("failed to wait for transaction"))
        })?;

        if !status.is_confirmed() {
            error!("Faucet funding failed");
            return Ok(AddFaucetFundsResponse {
                transaction_hash: status.tx_hash(),
                message: Some("Faucet funding failed".to_string()),
            });
        }

        Ok(AddFaucetFundsResponse {
            transaction_hash: status.tx_hash(),
            message: Some("Faucet funding successful".to_string()),
        })
    }
}

/// Implementation of the Ithaca `relay_` namespace.
#[derive(Debug)]
pub(super) struct RelayInner {
    /// The contract addresses.
    contracts: VersionedContracts,
    /// The chains supported by the relay.
    chains: Arc<Chains>,
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
    /// Escrow refund threshold in seconds
    escrow_refund_threshold: u64,
}

impl Relay {
    /// The orchestrator address.
    pub fn orchestrator(&self) -> Address {
        self.inner.contracts.orchestrator.address
    }

    /// Get previously deployed orchestrator and simulator by orchestrator address.
    pub fn get_legacy_orchestrator(
        &self,
        address: Address,
    ) -> Option<&VersionedOrchestratorContracts> {
        self.inner
            .contracts
            .legacy_orchestrators
            .iter()
            .find(|contracts| contracts.orchestrator.address == address)
    }

    /// Get the simulator address for the given orchestrator address.
    /// Returns the matching simulator for the orchestrator (current or legacy).
    pub fn get_simulator_for_orchestrator(&self, orchestrator_address: Address) -> Address {
        if orchestrator_address == self.orchestrator() {
            // Current orchestrator uses current simulator
            self.simulator()
        } else if let Some(legacy) = self.get_legacy_orchestrator(orchestrator_address) {
            // Legacy orchestrator uses its corresponding simulator
            legacy.simulator.address
        } else {
            // Fallback to current simulator if orchestrator not found
            self.simulator()
        }
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
        self.inner.chains.interop().ok_or(QuoteError::MultichainDisabled)?;
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
            settler: self.inner.chains.settler_address(context.chain_id)?,
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
