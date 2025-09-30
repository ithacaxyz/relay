//! # Ithaca Relay RPC
//!
//! Implementations of a custom `relay_` namespace.

use crate::{
    asset::AssetInfoServiceHandle,
    constants::{COLD_SSTORE_GAS_BUFFER, ESCROW_SALT_LENGTH, P256_GAS_BUFFER},
    error::{IntentError, StorageError},
    estimation::fees::approx_intrinsic_cost,
    provider::ProviderExt,
    rpc::ExtraFeeInfo,
    signers::Eip712PayLoadSigner,
    transactions::interop::InteropBundle,
    types::{
        Account, Asset, AssetDeficit, AssetDiffResponse, AssetMetadataWithPrice, AssetPrice,
        AssetType, Call, ChainAssetDiffs, DelegationStatus, Escrow, FundSource,
        FundingIntentContext, GasEstimate, Health, IERC20, IEscrow, IntentKey, IntentKind, Intents,
        Key, MULTICHAIN_NONCE_PREFIX, MerkleLeafInfo,
        OrchestratorContract::{self, IntentExecuted},
        Quotes, SignedCall, SignedCalls, SourcedAsset, Transfer, VersionedContracts,
        rpc::{
            AddFaucetFundsParameters, AddFaucetFundsResponse, AddressOrNative, Asset7811,
            AssetFilterItem, CallKey, CallReceipt, CallStatusCode, ChainCapabilities,
            ChainFeeToken, ChainFees, GetAssetsParameters, GetAssetsResponse,
            GetAuthorizationParameters, GetAuthorizationResponse, Meta, PreCallContext,
            PrepareCallsCapabilities, PrepareCallsContext, PrepareUpgradeAccountResponse,
            RelayCapabilities, RequiredAsset, SendPreparedCallsCapabilities, UpgradeAccountContext,
            UpgradeAccountDigests, ValidSignatureProof,
        },
    },
    version::RELAY_SHORT_VERSION,
};
use alloy::{
    consensus::{TxEip1559, TxEip7702},
    eips::{eip1559::Eip1559Estimation, eip7702::SignedAuthorization},
    primitives::{
        Address, B256, BlockNumber, Bytes, ChainId, TxKind, U64, U256,
        aliases::{B192, U192},
        bytes,
        map::HashSet,
    },
    providers::{DynProvider, Provider, utils::EIP1559_FEE_ESTIMATION_PAST_BLOCKS},
    rlp::Encodable,
    rpc::types::{Authorization, TransactionRequest},
    sol_types::{SolCall, SolValue},
};
use alloy_chains::NamedChain;
use futures::{StreamExt, stream::FuturesOrdered};
use futures_util::{TryStreamExt, future::try_join_all, join, stream::FuturesUnordered};
use itertools::Itertools;
use jsonrpsee::{
    core::{RpcResult, async_trait},
    proc_macros::rpc,
};
use opentelemetry::trace::SpanKind;
use std::{cmp, collections::HashMap, sync::Arc, time::SystemTime};
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
        CreatableAccount, FeeEstimationContext, Intent, KeyWith712Signer, Orchestrator,
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
        let capabilities: FuturesUnordered<_> = chains
            .into_iter()
            .filter_map(|chain_id| {
                // Relay needs a chain endpoint to support a chain.
                let chain = self.inner.chains.get(chain_id)?;
                let provider = chain.provider().clone();
                let native_uid = chain.assets().native()?.0.clone();
                let fee_tokens = chain.assets().fee_tokens();

                Some(async move {
                    let fee_tokens =
                        try_join_all(fee_tokens.into_iter().map(|(token_uid, token)| {
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
                            contracts: self.contracts().clone(),
                            fees: ChainFees {
                                recipient: self.inner.fee_recipient,
                                quote_config: self.inner.quote_config.clone(),
                                tokens: fee_tokens,
                            },
                        },
                    ))
                })
            })
            .collect();

        Ok(RelayCapabilities(capabilities.try_collect().await?))
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
    ) -> Result<ExtraFeeInfo, RelayError> {
        // Include the L1 DA fees if we're on an OP or Arbitrum rollup.
        if chain.is_optimism() {
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
                    to: self.contracts().orchestrator(),
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
                    to: self.contracts().orchestrator().into(),
                    input: intent.encode_execute(),
                    ..Default::default()
                }
                .encode(&mut buf);
            }

            let l1_fee = chain.provider().estimate_l1_op_fee(buf.into()).await?;
            Ok(ExtraFeeInfo::Optimism { l1_fee })
        } else if chain.is_arbitrum() {
            let gas_estimate = chain
                .provider()
                .estimate_l1_arb_fee_gas(
                    chain.id(),
                    self.contracts().orchestrator(),
                    gas_estimate.tx,
                    *fees,
                    auth,
                    intent.encode_execute(),
                )
                .await?;

            Ok(ExtraFeeInfo::Arbitrum { gas_estimate })
        } else {
            Ok(ExtraFeeInfo::None)
        }
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
        let mock_key = KeyWith712Signer::random_admin(context.key.key_type())
            .map_err(RelayError::from)
            .and_then(|k| k.ok_or_else(|| RelayError::Keys(KeysError::UnsupportedKeyType)))?;
        // create a mock transaction signer
        let mock_from = Address::random();

        // Prepare futures for concurrent execution
        // Fetch balance for fee_payer (already coalesced to EOA if not specified)
        let fee_payer_balance_fut = self.get_assets(GetAssetsParameters::for_asset_on_chain(
            context.fee_payer,
            chain_id,
            context.fee_token,
        ));

        let priority_fee_percentiles = [chain.fee_config().priority_fee_percentile];
        let fee_history_fut = provider.get_fee_history(
            EIP1559_FEE_ESTIMATION_PAST_BLOCKS,
            Default::default(),
            &priority_fee_percentiles,
        );

        let native_price_fut =
            self.inner.price_oracle.native_conversion_rate(token_uid.clone(), native_uid.clone());

        // Execute all futures in parallel and handle errors
        let (assets_response, fee_history, eth_price) = try_join!(
            async { fee_payer_balance_fut.await.map_err(RelayError::internal) },
            async { fee_history_fut.await.map_err(RelayError::from) },
            async { Ok(native_price_fut.await) }
        )?;

        let fee_token_balance =
            assets_response.balance_on_chain(chain_id, context.fee_token.into());

        let fee_token_funding = intent
            .fund_transfers
            .iter()
            .filter(|(token, _)| *token == context.fee_token)
            .map(|(_, amount)| amount)
            .sum::<U256>();

        // Build state overrides for simulation
        let overrides = chain
            .build_simulation_overrides(&intent, &context, mock_from, fee_token_balance)
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

        if !intent_to_sign.encoded_fund_transfers().is_empty() {
            intent_to_sign = intent_to_sign.with_funder(self.contracts().funder());
        }

        // For simulation purposes we only simulate with a payment of 1 unit of the fee token. This
        // should be enough to simulate the gas cost of paying for the intent for most (if not all)
        // ERC20s.
        //
        // Additionally, we included a balance override of `balance + 1` unit of the fee token,
        // which ensures the simulation never reverts. Whether the user can actually really
        // pay for the intent execution or not is determined later and communicated to the
        // client.
        intent_to_sign.set_payment(U256::from(1));

        if intent_to_sign.is_interop() {
            // For multichain intents, add a mocked merkle signature
            intent_to_sign = intent_to_sign
                .with_mock_merkle_signature(
                    &context.intent_kind,
                    orchestrator.versioned_contract(),
                    chain.id(),
                    &mock_key,
                    &context.key,
                    prehash,
                )
                .await
                .map_err(RelayError::from)?;
        } else {
            // For single chain intents, sign the intent directly
            let signature = mock_key
                .sign_payload_hash(
                    intent_to_sign
                        .compute_eip712_data(orchestrator.versioned_contract(), chain.id())?
                        .0,
                )
                .await
                .map_err(RelayError::from)?;

            intent_to_sign =
                intent_to_sign.with_signature(context.key.wrap_signature(signature, prehash));
        };

        let gas_validation_offset =
            // Account for gas variation in P256 sig verification.
            if context.key.key_type().is_secp256k1() { U256::ZERO } else { P256_GAS_BUFFER }
                // Account for the case when we change zero fee token balance to non-zero, thus skipping a cold storage write
                // We're adding 1 wei to the balance in build_simulation_overrides, so it will be non-zero if fee_token_balance is zero
                + if fee_token_balance.is_zero() && !context.fee_token.is_zero() {
                    COLD_SSTORE_GAS_BUFFER
                } else {
                    U256::ZERO
                };

        // Simulate the intent
        let (asset_diffs, mut asset_deficits, gas_results) = orchestrator
            .simulate_execute(
                mock_from,
                self.contracts().get_simulator_for_orchestrator(*orchestrator.address()),
                &intent_to_sign,
                self.inner.asset_info.clone(),
                gas_validation_offset,
                chain.sim_mode(),
                context.calculate_asset_deficits,
                chain.erc20_slots(),
            )
            .await?;

        let intrinsic_gas = approx_intrinsic_cost(
            &intent_to_sign.encode_execute(),
            context.stored_authorization.is_some(),
        );

        let mut gas_estimate = GasEstimate::from_combined_gas(
            gas_results.gCombined.to(),
            intrinsic_gas,
            &self.inner.quote_config,
        );
        debug!(eoa = %intent.eoa, gas_estimate = ?gas_estimate, "Estimated intent");

        // Fill combinedGas
        intent_to_sign = intent_to_sign.with_combined_gas(U256::from(gas_estimate.intent));
        // Calculate the real fee
        let extra_fee_info = self
            .estimate_extra_fee(
                &chain,
                &intent_to_sign,
                context.stored_authorization.clone(),
                &native_fee_estimate,
                &gas_estimate,
            )
            .await?;

        // this should return zero on all non-arbitrum chains, we add this to the gaslimit
        gas_estimate.tx += extra_fee_info.extra_gas();

        let extra_fee_native = extra_fee_info.extra_fee();
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

        // Find amount of fee token spent by this intent.
        let fee_token_spending = asset_diffs
            .0
            .iter()
            .find(|(address, _)| *address == intent.eoa)
            .and_then(|(_, diffs)| {
                diffs.iter().find(|diff| diff.address.unwrap_or_default() == context.fee_token)
            })
            .map(|diff| {
                if diff.direction.is_outgoing() {
                    // intent spent entire funding along with some extra amount
                    diff.value.saturating_add(fee_token_funding)
                } else {
                    // the actual spending here might be negative but we cap it at
                    // `fee_token_funding` as this is the maximum amount that can be spent on the
                    // fees (everything else is received after fee payment)
                    fee_token_funding.saturating_sub(diff.value)
                }
            })
            .unwrap_or(fee_token_funding);

        // Calculate fee token deficit accounting for any additional spending
        let fee_token_deficit = intent_to_sign.total_payment_max_amount().saturating_sub(
            fee_token_balance.saturating_add(fee_token_funding).saturating_sub(fee_token_spending),
        );

        // Record fee token deficit in asset deficits only if no fee_payer was specified
        // If there's a fee_payer, the deficit is their responsibility, not the user's
        if !fee_token_deficit.is_zero() && intent_to_sign.payer().is_zero() {
            if let Some(existing) = asset_deficits
                .0
                .iter_mut()
                .find(|asset| asset.address.unwrap_or_default() == context.fee_token)
            {
                existing.deficit += intent_to_sign.total_payment_max_amount();
                existing.required += intent_to_sign.total_payment_max_amount();
            } else if let Some(metadata) = self
                .inner
                .asset_info
                .get_asset_info_list(&provider, vec![Asset::Token(context.fee_token)])
                .await?
                .remove(&Asset::Token(context.fee_token))
                .map(|info| info.metadata)
            {
                asset_deficits.0.push(AssetDeficit {
                    address: (!context.fee_token.is_zero()).then_some(context.fee_token),
                    metadata,
                    required: intent_to_sign.total_payment_max_amount() + fee_token_spending,
                    deficit: fee_token_deficit,
                    fiat: None,
                });
            } else {
                debug!(fee_token = %context.fee_token, "No metadata found for fee token");
            }
        }

        let quote = Quote {
            chain_id,
            payment_token_decimals: token.decimals,
            intent: intent_to_sign,
            extra_payment,
            eth_price,
            tx_gas: gas_estimate.tx,
            native_fee_estimate,
            authorization_address: context.stored_authorization.as_ref().map(|auth| auth.address),
            additional_authorization: context.additional_authorization.map(|(_, auth)| auth),
            orchestrator: *orchestrator.address(),
            fee_token_deficit,
            asset_deficits,
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
    ) -> RpcResult<BundleId> {
        // if we do **not** get an error here, then the quote ttl must be in the past, which means
        // it is expired
        if SystemTime::now().duration_since(quotes.ty().ttl).is_ok() {
            return Err(QuoteError::QuoteExpired.into());
        }

        // If any of the quotes have deficits, return an error
        if quotes.ty().quotes.iter().any(|q| q.has_deficits()) {
            return Err(QuoteError::QuoteHasDeficits.into());
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

        // Use multichain workflow if there's a merkle root OR a fee_payer quote
        if quotes.ty().multi_chain_root.is_none() && quotes.ty().fee_payer.is_none() {
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
        externally_sponsored: bool,
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
        let (eip712_digest, _) = quote.intent.compute_eip712_data(
            self.contracts().get_versioned_orchestrator(quote.orchestrator)?,
            chain_id,
        )?;

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
                .with_funder(self.contracts().funder());
        }

        // Set non-eip712 payment fields. Since they are not included into the signature so we
        // need to enforce it here.
        let payment_amount = quote.intent.pre_payment_max_amount();
        quote.intent.set_payment(payment_amount);

        // we have a list of potential auths
        let mut authorization_list = Vec::new();

        // if the additional auth exists, push it
        authorization_list.extend(quote.additional_authorization.clone());

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

        // push auth if exists
        authorization_list.extend(authorization.clone());

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

        let tx =
            RelayTransaction::new(quote, authorization_list, eip712_digest, externally_sponsored);
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
        chains
            .into_iter()
            .map(|chain_id| async move {
                self.get_keys_for_chain(address, chain_id)
                    .await
                    .map(|keys| (U64::from(chain_id), keys))
            })
            .collect::<FuturesUnordered<_>>()
            .try_collect()
            .await
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

    /// Given a key hash and a list of [`PreCall`], it tries to find a key for the requested
    /// identity.
    ///
    /// If it cannot find it, it will attempt to fetch it from storage or on-chain.
    ///
    /// If it's not found in the storage or on-chain, it checks if the identity is derived from the
    /// root EOA key, and if so, returns the root EOA key.
    #[instrument(skip_all)]
    async fn try_find_key(
        &self,
        identity: &IdentityParameters,
        pre_calls: &[SignedCall],
        chain_id: ChainId,
    ) -> Result<Option<IntentKey<Key>>, RelayError> {
        if identity.key.is_eoa_root_key() {
            return Ok(Some(IntentKey::EoaRootKey));
        }

        for pre_call in pre_calls {
            if let Some(key) = pre_call
                .authorized_keys()?
                .iter()
                .find(|key| key.key_hash() == identity.key.key_hash())
            {
                return Ok(Some(IntentKey::StoredKey(key.clone())));
            }
        }

        // Get keys for the specific chain (treat errors as no keys available)
        if let Some(key) = self
            .get_keys_for_chain(identity.root_eoa, chain_id)
            .await?
            .iter()
            .find(|k| k.hash == identity.key.key_hash())
            .map(|k| k.authorize_key.key.clone())
        {
            return Ok(Some(IntentKey::StoredKey(key)));
        }

        Ok(None)
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
        let versioned_contract = self.contracts().get_versioned_orchestrator(address)?;
        Ok(Orchestrator::new(versioned_contract.clone(), provider))
    }

    /// Checks if a delegation implementation needs upgrading.
    ///
    /// Returns Some(new_impl) if upgrade needed, None if current.
    /// Returns error if delegation is neither current nor legacy (unsupported).
    fn maybe_delegation_upgrade(
        &self,
        current_implementation: Address,
    ) -> Result<Option<Address>, RelayError> {
        let current = self.contracts().delegation_implementation();

        // Check if it's the current implementation (up to date)
        if current_implementation == current {
            return Ok(None);
        }

        // Check if it's a legacy implementation (needs upgrade)
        if self.contracts().legacy_delegations().any(|c| c == current_implementation) {
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
                fee_payer: account.address,
                stored_authorization: Some(account.signed_authorization.clone()),
                key: IntentKey::EoaRootKey,
                additional_authorization: None,
                intent_kind: IntentKind::Single,
                state_overrides: Default::default(),
                balance_overrides: Default::default(),
                calculate_asset_deficits: false,
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
        identity: &IdentityParameters,
        delegation_status: &DelegationStatus,
        nonce: U256,
        intent_kind: IntentKind,
        calculate_asset_deficits: bool,
    ) -> Result<(ChainAssetDiffs, Quote), RelayError> {
        let eoa = identity.root_eoa;
        let key_hash = identity.key.key_hash();

        let provider = self.provider(request.chain_id)?;

        let mut account = Account::new(eoa, &provider);
        if let Some(stored) = delegation_status.stored_account() {
            account = account.with_overrides(stored.state_overrides()?);
        }

        let delegation_implementation = delegation_status.try_implementation()?;

        let seq_to_stored_precalls = self
            .inner
            .storage
            .read_precalls_for_eoa(request.chain_id, eoa)
            .await?
            .into_iter()
            // Only retain precalls that are relevant for this intent's signing key.
            .filter(|call| {
                call.calls().is_ok_and(|calls| {
                    calls.iter().any(|call| call.decode_precall_key_hash() == Some(key_hash))
                })
            })
            .sorted_by_key(|call| call.nonce)
            .fold(HashMap::new(), |mut acc, call| {
                acc.entry(call.nonce >> 64).or_insert_with(Vec::new).push(call);
                acc
            });

        let mut stored_precalls = Vec::new();
        for (seq_key, calls) in seq_to_stored_precalls {
            let mut nonce = account.get_nonce_for_sequence(U192::from(seq_key)).await?;
            for call in calls {
                if call.nonce == nonce {
                    stored_precalls.push(call);
                    nonce += U256::from(1);
                } else if call.nonce < nonce {
                    // Remove if nonce is already used.
                    self.inner.storage.remove_precall(request.chain_id, eoa, call.nonce).await?;
                } else {
                    // If nonce is greater, we have a nonce gap which we should skip.
                    break;
                }
            }
        }

        let mut pre_calls = request
            .capabilities
            .pre_calls
            .iter()
            .cloned()
            .chain(stored_precalls)
            .collect::<Vec<_>>();

        let mut calls = request.calls.clone();

        // Check if upgrade is needed (only for delegated accounts)
        if let Some(new_impl) = self.maybe_delegation_upgrade(delegation_implementation)? {
            calls.push(Call::upgrade_proxy_account(new_impl));
        }

        let mut additional_authorization = None;

        // delegate the fee payer if it is stored, only adding a precall if it's for delegation to
        // an ithaca account, assuming the configured delegation account is an ithaca account.
        if let Some(fee_payer) = request.capabilities.meta.fee_payer {
            // check if delegation is needed
            let delegation_status = self.delegation_status(&fee_payer, request.chain_id).await?;

            if let DelegationStatus::Stored { account, implementation } = delegation_status {
                // check if the implementation is at least v0.5.6. before ithaca account v0.5.6, the
                // contracts had a check which required all precalls to be signed by the eoa
                if self.is_ithaca_account(implementation, semver::Version::new(0, 5, 6)) {
                    // put the delegation as the first call
                    pre_calls.insert(0, account.pre_call.clone());
                    additional_authorization = Some((fee_payer, account.signed_authorization))
                }
            }
        }

        // Find the key that authorizes this intent
        let Some(key) = self.try_find_key(identity, &pre_calls, request.chain_id).await? else {
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
                    eoa: identity.root_eoa,
                    execution_data: calls.abi_encode().into(),
                    nonce,
                    payer: request.capabilities.meta.fee_payer,
                    // stored PreCall should come first since it's been signed by the root
                    // EOA key.
                    pre_calls: delegation_status
                        .stored_account()
                        .iter()
                        .map(|acc| acc.pre_call.clone())
                        .chain(pre_calls)
                        .collect(),
                    // sort fund transfers by token address to ensure that native comes first as
                    // required by the orchestrator
                    fund_transfers: intent_kind
                        .fund_transfers()
                        .into_iter()
                        .sorted_by_key(|(token, _)| *token)
                        .collect(),
                    delegation_implementation,
                },
                request.chain_id,
                identity.key.prehash(),
                FeeEstimationContext {
                    // fee_token should have been set in the beginning of prepare_calls_inner if it
                    // was not provided by the user
                    fee_token: request.capabilities.meta.fee_token.unwrap_or(Address::ZERO),
                    fee_payer: request.capabilities.meta.fee_payer.unwrap_or(identity.root_eoa),
                    stored_authorization: delegation_status
                        .stored_account()
                        .map(|acc| acc.signed_authorization.clone()),
                    additional_authorization,
                    key,
                    intent_kind,
                    state_overrides,
                    balance_overrides,
                    calculate_asset_deficits,
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

    /// Checks if the provided address points to an ithaca account, with the desired version or
    /// higher.
    fn is_ithaca_account(&self, implementation: Address, min_version: semver::Version) -> bool {
        self.contracts()
            .get_delegation_implementation_version(implementation)
            .map(|v| v >= min_version)
            .unwrap_or(false)
    }

    #[instrument(skip_all)]
    async fn prepare_calls_inner(
        &self,
        mut request: PrepareCallsParameters,
    ) -> RpcResult<PrepareCallsResponse> {
        // Checks calls and precall calls in the request
        request.check_calls(self.contracts().delegation_implementation())?;

        let provider = self.provider(request.chain_id)?;

        // Get delegation status and ensure fee_token is set (only for non-pre_call)
        let delegation_status = if let Some(from) = request.from {
            // Fetch account assets and status in parallel if we need to auto-select fee token
            if !request.capabilities.pre_call && request.capabilities.meta.fee_token.is_none() {
                let chain = self.inner.chains.ensure_chain(request.chain_id)?;
                let fee_payer = request.capabilities.meta.fee_payer.unwrap_or(from);

                let (status, _) =
                    tokio::try_join!(self.delegation_status(&from, request.chain_id), async {
                        let assets = self
                            .get_assets(GetAssetsParameters::for_chain(fee_payer, request.chain_id))
                            .await
                            .map_err(RelayError::internal)?;
                        request.capabilities.meta.fee_token = Some(
                            assets.find_best_fee_token(&chain, &self.inner.price_oracle).await,
                        );
                        Ok(())
                    })?;
                Some(status)
            } else {
                Some(self.delegation_status(&from, request.chain_id).await?)
            }
        } else {
            None
        };

        // Generate all requested calls.
        request.calls = self.generate_calls(&request)?;

        // Get next available nonce for DEFAULT_SEQUENCE_KEY
        let nonce = request
            .get_nonce(
                delegation_status.as_ref().and_then(|s| s.stored_account()),
                &provider,
                &self.inner.storage,
            )
            .await?;

        // If we're dealing with a PreCall do not estimate
        let (asset_diff, context, key, fee_payer_digest) = if request.capabilities.pre_call {
            let call = SignedCall {
                eoa: request.from.unwrap_or_default(),
                executionData: request.calls.abi_encode().into(),
                nonce,
                signature: Bytes::new(),
            };

            (
                AssetDiffResponse::default(),
                PrepareCallsContext::with_precall(PreCallContext {
                    call,
                    chain_id: request.chain_id,
                }),
                request.key.clone(),
                None,
            )
        } else {
            // Regular flow - sender and delegation status are required
            let Some(ref delegation_status) = delegation_status else {
                // delegation_status is None, only if we haven't received a from in the parameters
                return Err(IntentError::MissingSender.into());
            };

            let eoa = request.from.ok_or(IntentError::MissingSender)?;
            let identity = IdentityParameters::new(request.key.as_ref(), eoa);

            let (asset_diffs, quotes) =
                self.build_quotes(&request, &identity, nonce, delegation_status).await?;

            // Extract fee_payer digest if present
            // If there's a cross-chain fee_payer (quotes.fee_payer is Some), use its digest
            // If fee_payer is specified but same-chain (quotes.fee_payer is None), use main digest
            let fee_payer_digest = request.capabilities.meta.fee_payer.and_then(|_| {
                quotes.fee_payer.as_ref().map(|fp| fp.intent.digest()).or(Some(quotes.digest()))
            });

            let sig = self
                .inner
                .quote_signer
                .sign_hash(&quotes.digest())
                .await
                .map_err(|err| RelayError::InternalError(err.into()))?;

            (
                asset_diffs,
                PrepareCallsContext::with_quotes(quotes.into_signed(sig)),
                identity.key.into_stored_key(),
                fee_payer_digest,
            )
        };

        // Calculate the digest and check if ERC1271 wrapping is needed in parallel
        let ((mut digest, typed_data), should_wrap_erc1271) = tokio::try_join!(
            async {
                context
                    .compute_signing_digest(
                        delegation_status.as_ref().and_then(|s| s.stored_account()),
                        self.contracts(),
                        &provider,
                    )
                    .await
            },
            self.should_erc1271_wrap(&request, &delegation_status, &provider)
        )?;

        // Wrap digest for ERC1271 validation if needed
        if let Some(key_address) = should_wrap_erc1271 {
            digest = Account::new(key_address, provider.clone()).digest_erc1271(digest);
        }

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
                fee_payer_digest,
                asset_diff,
            },
            key,
            signature: Bytes::new(),
        }
        .with_signature(&self.inner.quote_signer)
        .await
        .map_err(RelayError::InternalError)?;

        Ok(response)
    }

    /// Generates a list of chain and amounts that fund a target chain operation.
    ///
    /// # Returns
    ///
    /// Returns `None` if there were not enough funds across all chains.
    ///
    /// Returns `Some(vec![])` if the destination chain does not require any funding from other
    /// chains.
    #[instrument(skip(self, identity, assets))]
    async fn source_funds(
        &self,
        identity: &IdentityParameters,
        assets: &GetAssetsResponse,
        destination_chain_id: ChainId,
        destination_orchestrator: Address,
        requested_assets: Vec<(AddressOrNative, U256)>,
        total_leaves: usize,
    ) -> Result<Option<Vec<FundSource>>, RelayError> {
        let mut remaining = HashMap::new();

        for (asset, amount) in &requested_assets {
            let existing_balance = assets
                .asset_on_chain(destination_chain_id, *asset)
                .map(|asset| asset.balance)
                .unwrap_or_default();

            let remaining_amount = amount.saturating_sub(existing_balance);

            if remaining_amount.is_zero() {
                continue;
            }

            remaining.insert(asset, remaining_amount);
        }

        if remaining.is_empty() {
            return Ok(Some(vec![]));
        }

        // collect mapping from chain to all non-zero balances on it.
        let sources = assets
            .0
            .iter()
            .filter(|(chain, _)| **chain != destination_chain_id)
            .flat_map(|(chain, assets)| assets.iter().map(|asset| (*chain, asset)))
            .fold(HashMap::new(), |mut acc, (chain, asset)| {
                let Some(on_dst) = self
                    .inner
                    .chains
                    .map_interop_asset(chain, destination_chain_id, asset.address.address())
                    .map(|a| a.address)
                else {
                    return acc;
                };

                if !requested_assets.iter().any(|(requested, _)| requested.address() == on_dst) {
                    return acc;
                }

                if asset.balance.is_zero() {
                    return acc;
                }

                acc.entry(chain).or_insert_with(Vec::new).push((asset.address, asset.balance));
                acc
            });

        // Simulate funding intents in parallel, preserving the order
        let mut funding_intents = sources
            .into_iter()
            // sort balances by value on destination chain. we sort in descending order to ensure
            // that we try chains with the highest balance first
            //
            // todo: find a better way to do this. right now this only works well for single asset
            // case.
            .sorted_unstable_by_key(|(chain, assets)| {
                let balances = requested_assets
                    .iter()
                    .map(|(asset, _)| {
                        let Some(mapped) = self.inner.chains.map_interop_asset(
                            destination_chain_id,
                            *chain,
                            asset.address(),
                        ) else {
                            return U256::ZERO;
                        };

                        let Some(dst_decimals) = self
                            .inner
                            .chains
                            .asset(destination_chain_id, mapped.address)
                            .map(|(_, desc)| desc.decimals)
                        else {
                            return U256::ZERO;
                        };

                        let balance = assets
                            .iter()
                            .find(|(asset, _)| asset.address() == mapped.address)
                            .map(|(_, balance)| *balance)
                            .unwrap_or_default();

                        adjust_balance_for_decimals(balance, mapped.decimals, dst_decimals)
                    })
                    .collect::<Vec<_>>();

                cmp::Reverse(balances)
            })
            .map(|(chain, balances)| async move {
                // todo: this might not work well for multi asset case.
                let fee_token = balances.first().unwrap().0.address();
                // we simulate escrowing the smallest unit of the asset to get a sense of the fees
                let funding_context = FundingIntentContext {
                    eoa: identity.root_eoa,
                    chain_id: chain,
                    assets: balances.iter().map(|(asset, _)| (*asset, U256::from(1))).collect(),
                    fee_token,
                    // note(onbjerg): it doesn't matter what the output intent digest is for
                    // simulation, as long as it's not zero. otherwise, the gas
                    // costs will differ a lot.
                    output_intent_digest: B256::with_last_byte(1),
                    output_chain_id: destination_chain_id,
                    output_orchestrator: destination_orchestrator,
                };
                let escrow_cost = self
                    .simulate_funding_intent(
                        funding_context,
                        identity,
                        MerkleLeafInfo { total: total_leaves, index: 0 },
                        None,
                    )
                    .await?
                    .1
                    .intent
                    .total_payment_max_amount();

                Result::<_, RelayError>::Ok((chain, balances, fee_token, escrow_cost))
            })
            .collect::<FuturesOrdered<_>>();

        let mut plan = Vec::new();
        while let Some((chain, balances, fee_token, escrow_cost)) =
            funding_intents.next().await.transpose()?
        {
            let mut taken_assets = Vec::new();

            remaining.retain(|asset, remaining| {
                let Some(mapped) = self.inner.chains.map_interop_asset(
                    destination_chain_id,
                    chain,
                    asset.address(),
                ) else {
                    return true;
                };

                let Some((_, balance)) =
                    balances.iter().find(|(asset, _)| asset.address() == mapped.address)
                else {
                    return true;
                };

                let Some(dst_decimals) = self
                    .inner
                    .chains
                    .asset(destination_chain_id, mapped.address)
                    .map(|(_, desc)| desc.decimals)
                else {
                    return true;
                };

                // Calculate the maximum amount we can bridge to destination
                let max_take = adjust_balance_for_decimals(
                    if fee_token == mapped.address {
                        (*balance).saturating_sub(escrow_cost)
                    } else {
                        *balance
                    },
                    mapped.decimals,
                    dst_decimals,
                );

                if max_take.is_zero() {
                    return true;
                }

                let take = (*remaining).min(max_take);

                // Convert the amount back to the source chain asset decimals
                let amount_source =
                    adjust_balance_for_decimals(take, dst_decimals, mapped.decimals);

                *remaining -= take;

                taken_assets.push(SourcedAsset {
                    address_source: mapped.address,
                    address_destination: asset.address(),
                    amount_source,
                    amount_destination: take,
                });

                !remaining.is_zero()
            });

            if !taken_assets.is_empty() {
                plan.push(FundSource {
                    chain_id: chain,
                    assets: taken_assets,
                    fee_token,
                    cost: escrow_cost,
                });
            }

            if remaining.is_empty() {
                break;
            }
        }

        if remaining.is_empty() {
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
    async fn build_quotes(
        &self,
        request: &PrepareCallsParameters,
        identity: &IdentityParameters,
        nonce: U256,
        delegation_status: &DelegationStatus,
    ) -> RpcResult<(AssetDiffResponse, Quotes)> {
        let requested_with_balances = if !request.capabilities.required_funds.is_empty() {
            let requested_balances = self
                .get_assets(GetAssetsParameters::for_assets_on_chains(
                    identity.root_eoa,
                    HashMap::from([(
                        request.chain_id,
                        request
                            .capabilities
                            .required_funds
                            .iter()
                            .map(|requested_asset| requested_asset.address)
                            .collect(),
                    )]),
                ))
                .await?;

            request
                .capabilities
                .required_funds
                .iter()
                .map(|requested_asset| {
                    (
                        *requested_asset,
                        requested_balances
                            .balance_on_chain(request.chain_id, requested_asset.address.into()),
                    )
                })
                .collect()
        } else {
            vec![]
        };

        let (requested_with_balance, single_chain_quote) = if requested_with_balances
            .iter()
            .any(|(requested, balance)| requested.value > *balance)
        {
            // If requested assets are specified explicitly and we know that balance is not
            // enough, we can proceed to multichain estimation.
            (requested_with_balances, None)
        } else {
            // Otherwise, we try to simulate intent as single chain first.
            let quote_result = self
                .build_single_chain_quote(request, identity, delegation_status, nonce, true)
                .await?;

            // It should never happen that we do not have a quote from this simulation, but
            // to avoid outright crashing we just throw an internal
            // error.
            let quote = quote_result.1.quotes.first().ok_or_else(|| {
                RelayError::InternalError(eyre::eyre!("no quote after simulation"))
            })?;

            // If we could successfuly simulate the intent without any deficits, then we can
            // just do this single chain instead.
            // Exception: if fee_payer is set and has a deficit, create interop bundle for
            // cross-chain fee payment
            if quote.asset_deficits.is_empty() {
                // Check if this is a cross-chain fee payer case
                if !quote.fee_token_deficit.is_zero()
                    && !quote.intent.payer().is_zero()
                    && let Some((fee_payer_asset_diffs, fee_payer_quote)) = self
                        .build_fee_payer_quote(
                            std::slice::from_ref(quote),
                            quote.intent.payer(),
                            request.capabilities.meta.fee_token.unwrap_or_default(),
                        )
                        .await?
                {
                    debug!(
                        eoa = %identity.root_eoa,
                        chain_id = %request.chain_id,
                        fee_payer = %quote.intent.payer(),
                        fee_deficit = %quote.fee_token_deficit,
                        "Creating interop bundle for cross-chain fee payer"
                    );

                    // Return quotes with fee_payer quote attached
                    let (mut all_asset_diffs, mut quotes) = quote_result;
                    all_asset_diffs.push(fee_payer_quote.chain_id, fee_payer_asset_diffs);
                    quotes.fee_payer = Some(fee_payer_quote);

                    return Ok((all_asset_diffs, quotes));
                }

                debug!(
                    eoa = %identity.root_eoa,
                    chain_id = %request.chain_id,
                    fee = %quote.intent.total_payment_max_amount(),
                    "Falling back to single chain for intent"
                );

                return Ok(quote_result);
            }

            let mut deficits = quote.asset_deficits.0.clone();
            // Exclude the feeTokenDeficit from the deficit, we are handling it separately.
            deficits.retain_mut(|deficit| {
                if Some(deficit.address.unwrap_or_default()) != request.capabilities.meta.fee_token
                {
                    return true;
                }

                deficit.required =
                    deficit.required.saturating_sub(quote.intent.total_payment_max_amount());
                deficit.deficit = deficit.deficit.saturating_sub(quote.fee_token_deficit);

                // If the only deficit is the fee token deficit, we can keep it and handle
                // it as an interop intent requiring zero of the feeToken plus the fee.
                if deficit.deficit.is_zero() && quote.asset_deficits.0.len() == 1 {
                    true
                } else {
                    !deficit.deficit.is_zero()
                }
            });

            let mut requested_assets = Vec::new();

            for deficit in &deficits {
                // If interop is not enabled or not supported for the requested asset, we can't
                // proceed and should return quote with deficits.
                if self.inner.chains.interop().is_none()
                    || self
                        .inner
                        .chains
                        .interop_asset(request.chain_id, deficit.address.unwrap_or_default())
                        .is_none()
                {
                    return Ok(quote_result);
                }

                requested_assets.push((
                    RequiredAsset {
                        address: deficit.address.unwrap_or_default(),
                        value: deficit.required,
                    },
                    deficit.required.saturating_sub(deficit.deficit),
                ));
            }

            (requested_assets, Some(quote_result))
        };

        let fee_token = request.capabilities.meta.fee_token.unwrap_or_default();

        // Fetch funder's requested asset and fee token balances on destination chain
        let funder_assets = self
            .get_assets(GetAssetsParameters::for_assets_on_chains(
                self.contracts().funder(),
                HashMap::from([(
                    request.chain_id,
                    requested_with_balance
                        .iter()
                        .map(|asset| asset.0.address)
                        .chain(std::iter::once(fee_token))
                        .collect::<HashSet<_>>()
                        .into_iter()
                        .collect(),
                )]),
            ))
            .await?;

        let needed_funds = requested_with_balance
            .iter()
            .map(|(requested, balance)| {
                (requested.address, requested.value.saturating_sub(*balance))
            })
            .collect::<Vec<_>>();

        // Check if funder has sufficient liquidity for the requested asset
        for (asset, needed_funds) in &needed_funds {
            let funder_balance = funder_assets.balance_on_chain(request.chain_id, (*asset).into());

            if funder_balance < *needed_funds {
                return Err(QuoteError::InsufficientLiquidity.into());
            }
        }

        // At this point, we can assume that `requested_funds` are enough for intent to succeed
        // without the fees. Now we need to find a way to source the funds plus the fees.
        //
        // Simulate the output intent first to get the fees required to execute it.
        //
        // Note: We execute it as a multichain output, but without fund sources. The assumption here
        // is that the simulator will transfer the requested assets.
        let (_, mut output_quote) = self
            .build_intent(
                request,
                identity,
                delegation_status,
                nonce,
                IntentKind::MultiOutput {
                    leaf_index: 1,
                    fund_transfers: needed_funds,
                    settler_context: Vec::<ChainId>::new().abi_encode().into(),
                },
                false,
            )
            .await?;

        // ensure interop has been configured, before proceeding
        self.inner.chains.interop().ok_or(QuoteError::MultichainDisabled)?;

        // ensure the requested asset is supported for interop
        for (asset, _) in &requested_with_balance {
            self.inner.chains.interop_asset(request.chain_id, asset.address).ok_or(
                RelayError::UnsupportedAsset { chain: request.chain_id, asset: asset.address },
            )?;
        }

        // Get interop assets for the requested assets on source chains.
        let mut interop_assets = HashMap::new();
        for (asset, _) in &requested_with_balance {
            for (chain, asset) in
                self.inner.chains.map_interop_assets_per_chain(request.chain_id, asset.address)
            {
                interop_assets.entry(chain).or_insert_with(Vec::new).push(asset.address);
            }
        }

        // Include the fee token into the filter if we will need to source the fee as well.
        if !output_quote.fee_token_deficit.is_zero()
            && !requested_with_balance.iter().any(|(asset, _)| asset.address == fee_token)
        {
            for (chain, asset) in
                self.inner.chains.map_interop_assets_per_chain(request.chain_id, fee_token)
            {
                interop_assets.entry(chain).or_default().push(asset.address);
            }
        }

        // Fetch assets on the source chains.
        let assets = self
            .get_assets(GetAssetsParameters::for_assets_on_chains(
                identity.root_eoa,
                interop_assets,
            ))
            .await?;

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
                eoa = %identity.root_eoa,
                chain_id = %request.chain_id,
                ?requested_with_balance,
                %fee_token,
                fee = %output_quote.intent.total_payment_max_amount(),
                "Trying to source funds"
            );
            let mut requested_funds: Vec<(AddressOrNative, U256)> = requested_with_balance
                .iter()
                .map(|(asset, _)| (asset.address.into(), asset.value))
                .collect::<Vec<_>>();

            if let Some(entry) =
                requested_funds.iter_mut().find(|(address, _)| address.address() == fee_token)
            {
                entry.1 += output_quote.intent.total_payment_max_amount();
            } else if !output_quote.fee_token_deficit.is_zero() {
                requested_funds
                    .push((fee_token.into(), output_quote.intent.total_payment_max_amount()));
            }

            let Some(funding_chains) = self
                .source_funds(
                    identity,
                    &assets,
                    request.chain_id,
                    output_quote.orchestrator,
                    requested_funds.clone(),
                    num_funding_chains + 1,
                )
                .await?
            else {
                // We don't have enough funds across all chains, so we revert back to single chain
                // to produce a quote with a `feeTokenDeficit`.
                //
                // A more robust solution here is returning a `Result<Vec<FundSource>, Deficit>`
                // where the error specifies how much we have across all chains, and
                // we use that to produce the deficit, as the single chain
                // `feeTokenDeficit` is a bit misleading.
                let Some(quote) = single_chain_quote else {
                    return self
                        .build_single_chain_quote(request, identity, delegation_status, nonce, true)
                        .await
                        .map_err(Into::into);
                };
                return Ok(quote);
            };

            num_funding_chains = funding_chains.len();
            let input_chain_ids: Vec<ChainId> = funding_chains.iter().map(|s| s.chain_id).collect();
            let interop = self.inner.chains.interop().ok_or(QuoteError::MultichainDisabled)?;

            debug!(
                eoa = %identity.root_eoa,
                chain_id = %request.chain_id,
                ?requested_funds,
                %fee_token,
                fee = %output_quote.intent.total_payment_max_amount(),
                ?input_chain_ids,
                "Found potential fund sources"
            );

            // Encode the input chain IDs for the settler context
            let settler_context =
                interop.encode_settler_context(input_chain_ids).map_err(RelayError::from)?;

            let fund_transfers = funding_chains
                .iter()
                .flat_map(|source| source.assets.iter())
                .fold(HashMap::new(), |mut acc, asset| {
                    *acc.entry(asset.address_destination).or_insert(U256::ZERO) +=
                        asset.amount_destination;
                    acc
                })
                .into_iter()
                .collect::<Vec<_>>();

            // `sourced_funds` now also includes fees, so make sure the funder has enough balance to
            // transfer.
            for (token, amount) in &fund_transfers {
                let funder_balance_on_dst =
                    funder_assets.balance_on_chain(request.chain_id, (*token).into());
                if funder_balance_on_dst < *amount {
                    return Err(QuoteError::InsufficientLiquidity.into());
                }
            }

            // Simulate multi-chain
            let (output_asset_diffs, new_quote) = self
                .build_intent(
                    request,
                    identity,
                    delegation_status,
                    nonce,
                    IntentKind::MultiOutput {
                        leaf_index: num_funding_chains,
                        fund_transfers,
                        settler_context,
                    },
                    false,
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
            if output_quote.fee_token_deficit.is_zero() {
                // Compute EIP-712 digest (settlement_id)
                let (output_intent_digest, _) = output_quote.intent.compute_eip712_data(
                    self.contracts().get_versioned_orchestrator(output_quote.orchestrator)?,
                    output_quote.chain_id,
                )?;

                let funding_intents = try_join_all(funding_chains.iter().enumerate().map(
                    async |(leaf_index, source)| {
                        self.simulate_funding_intent(
                            FundingIntentContext {
                                eoa: identity.root_eoa,
                                chain_id: source.chain_id,
                                assets: source
                                    .assets
                                    .iter()
                                    .map(|asset| (asset.address_source.into(), asset.amount_source))
                                    .collect(),
                                fee_token: source.fee_token,
                                output_intent_digest,
                                output_chain_id: request.chain_id,
                                output_orchestrator: output_quote.orchestrator,
                            },
                            identity,
                            MerkleLeafInfo { total: num_funding_chains + 1, index: leaf_index },
                            // we override the fees here to avoid re-estimating. if we
                            // re-estimate, we might end up with
                            // a higher fee, which will invalidate the entire call.
                            Some(source.cost),
                        )
                        .await
                    },
                ))
                .await?;

                // Collect all quotes and build aggregated asset diff response
                let mut all_quotes = Vec::with_capacity(funding_intents.len() + 1);
                let mut all_asset_diffs = AssetDiffResponse::default();

                // Process source chains
                for (asset_diff, quote) in funding_intents {
                    all_asset_diffs.push(quote.chain_id, asset_diff);
                    all_quotes.push(quote);
                }

                // Add output chain
                all_quotes.push(output_quote);
                all_asset_diffs.push(request.chain_id, output_asset_diffs);

                // Handle fee_payer if specified
                let fee_payer_quote = if let Some(fee_payer) = request.capabilities.meta.fee_payer
                    && let Some((fee_payer_asset_diffs, fee_payer_quote)) =
                        self.build_fee_payer_quote(&all_quotes, fee_payer, fee_token).await?
                {
                    all_asset_diffs.push(fee_payer_quote.chain_id, fee_payer_asset_diffs);
                    Some(fee_payer_quote)
                } else {
                    None
                };

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
                        fee_payer: fee_payer_quote,
                    }
                    .with_merkle_payload(self.contracts())?,
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
        funding_context: FundingIntentContext,
        identity: &IdentityParameters,
        leaf_info: MerkleLeafInfo,
        fee: Option<U256>,
    ) -> Result<(ChainAssetDiffs, Quote), RelayError> {
        let fee = fee.map(|fee| (funding_context.fee_token, fee));

        let request = self.build_funding_intent(funding_context, identity.key.clone())?;

        let delegation_status =
            self.delegation_status(&identity.root_eoa, request.chain_id).await?;

        let nonce = request
            .get_nonce(
                delegation_status.stored_account(),
                &self.provider(request.chain_id)?,
                &self.inner.storage,
            )
            .await?;

        self.build_intent(
            &request,
            identity,
            &delegation_status,
            nonce,
            IntentKind::MultiInput { leaf_info, fee },
            false,
        )
        .await
    }

    /// Build a single-chain quote
    #[instrument(skip_all)]
    async fn build_single_chain_quote(
        &self,
        request: &PrepareCallsParameters,
        identity: &IdentityParameters,
        delegation_status: &DelegationStatus,
        nonce: U256,
        calculate_asset_deficits: bool,
    ) -> Result<(AssetDiffResponse, Quotes), RelayError> {
        let (asset_diffs, quote) = self
            .build_intent(
                request,
                identity,
                delegation_status,
                nonce,
                IntentKind::Single,
                calculate_asset_deficits,
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
                fee_payer: None,
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
                false, // single-chain intent is never externally sponsored
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
            self.create_interop_bundle(bundle_id, &mut quotes, &capabilities, signature).await?;

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
        signature: Bytes,
    ) -> Result<InteropBundle, RelayError> {
        let mut intents = Intents::new(
            quotes
                .ty()
                .quotes
                .iter()
                .map(|quote| {
                    self.contracts().get_versioned_orchestrator(quote.orchestrator).map(
                        |orchestrator| (quote.intent.clone(), orchestrator.clone(), quote.chain_id),
                    )
                })
                .collect::<Result<_, _>>()?,
        );

        // Create InteropBundle
        let interop = self.inner.chains.interop().ok_or(QuoteError::MultichainDisabled)?;
        let settler_id = interop.settler_id();
        let mut bundle = InteropBundle::new(bundle_id, settler_id);

        // last quote is the output intent
        let dst_idx = quotes.ty().quotes.len() - 1;

        let root = intents.root()?;
        let is_externally_sponsored = quotes.ty().fee_payer.is_some();
        let has_many_user_quotes = quotes.ty().quotes.len() > 1;

        let tx_futures = quotes.ty().quotes.iter().enumerate().map(async |(idx, quote)| {
            let signature = if has_many_user_quotes {
                let proof = intents.get_proof_immutable(idx)?;
                (proof, root, &signature).abi_encode_params().into()
            } else {
                signature.clone()
            };

            self.prepare_tx(
                bundle_id,
                quote.clone(),
                capabilities.clone(),
                signature,
                is_externally_sponsored,
            )
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

        // Extract and build fee_payer transaction if present
        if let Some(fee_payer_quote) = quotes.ty().fee_payer.as_ref() {
            bundle.fee_payer_tx = Some(
                self.prepare_tx(
                    bundle_id,
                    (**fee_payer_quote).clone(),
                    Default::default(),
                    capabilities.fee_signature.clone(),
                    false,
                )
                .await
                .map_err(|e| RelayError::InternalError(e.into()))?,
            );
        }

        Ok(bundle)
    }

    /// Gets the token price for an asset, only returns a price if it's a fee token and the inner
    /// price fetch is successful
    async fn get_token_price(&self, chain: u64, asset: &AssetFilterItem) -> Option<AssetPrice> {
        let (uid, _) = self.inner.chains.fee_token(chain, asset.address.address())?;
        self.inner.price_oracle.usd_conversion_rate(uid.clone()).await.map(AssetPrice::from_price)
    }

    /// Fetches [`DelegationStatus`] for an EOA on a given chain.
    async fn delegation_status(
        &self,
        eoa: &Address,
        chain: u64,
    ) -> Result<DelegationStatus, RelayError> {
        Account::new(*eoa, self.provider(chain)?).delegation_status(&self.inner.storage).await
    }

    /// Builds a fee payer quote for covering user transaction fees.
    ///
    /// This method finds the best chain where the fee payer has sufficient balance,
    /// creates a transfer intent, and returns the resulting quote.
    async fn build_fee_payer_quote(
        &self,
        all_quotes: &[Quote],
        fee_payer: Address,
        fee_token: Address,
    ) -> RpcResult<Option<(ChainAssetDiffs, Box<Quote>)>> {
        // Find the maximum decimals across all quotes
        let max_decimals = all_quotes.iter().map(|q| q.payment_token_decimals).max().unwrap_or(18);

        // Calculate total user fees by normalizing all payment amounts to max_decimals and summing
        let total_user_fees: U256 = all_quotes
            .iter()
            .map(|q| {
                let fee = q.intent.total_payment_max_amount();
                let decimals = q.payment_token_decimals;
                adjust_balance_for_decimals(fee, decimals, max_decimals)
            })
            .sum();

        // Fetch fee_payer's balance of fee_token only on chains where it exists
        let chains_with_fee_token: HashMap<ChainId, Vec<Address>> = self
            .inner
            .chains
            .chains_iter()
            .filter_map(|chain| {
                // Only include chains where this fee_token exists and is configured as a fee token
                self.inner
                    .chains
                    .fee_token(chain.id(), fee_token)
                    .map(|_| (chain.id(), vec![fee_token]))
            })
            .collect();

        let fee_payer_all_assets = self
            .get_assets(GetAssetsParameters::for_assets_on_chains(fee_payer, chains_with_fee_token))
            .await?;

        // Find chain with highest normalized balance that meets the threshold
        let source_chain = fee_payer_all_assets
            .0
            .iter()
            .filter_map(|(chain_id, assets)| {
                let asset = assets.iter().find(|a| a.address.address() == fee_token)?;
                let (_, token_desc) = self.inner.chains.fee_token(*chain_id, fee_token)?;
                let normalized =
                    adjust_balance_for_decimals(asset.balance, token_desc.decimals, max_decimals);
                (normalized >= total_user_fees).then_some((*chain_id, normalized))
            })
            .max_by_key(|(_, balance)| *balance)
            .map(|(chain_id, _)| chain_id);

        let Some(source_chain) = source_chain else {
            return Ok(None);
        };

        // Get fee_payer's delegation status on the source chain
        let fee_payer_delegation_status = self.delegation_status(&fee_payer, source_chain).await?;

        // Create identity parameters for fee_payer (use root EOA key for signing)
        let fee_payer_identity = IdentityParameters::new(None, fee_payer);

        // Get the payment recipient from the output quote (last quote in all_quotes)
        let output_quote = all_quotes.last().expect("all_quotes should contain at least one quote");
        let fee_recipient = output_quote.intent.payment_recipient();

        // Get the chosen chain's decimals and denormalize total_user_fees
        let (_, token_desc) = self
            .inner
            .chains
            .fee_token(source_chain, fee_token)
            .ok_or_else(|| RelayError::Quote(QuoteError::UnsupportedFeeToken(fee_token)))?;

        // Create a PartialIntent for fee_payer with the transfer call
        let fee_payer_request = PrepareCallsParameters {
            chain_id: source_chain,
            calls: vec![Call::transfer_fee(
                fee_token,
                fee_recipient,
                adjust_balance_for_decimals(total_user_fees, max_decimals, token_desc.decimals),
            )],
            from: Some(fee_payer),
            capabilities: PrepareCallsCapabilities {
                meta: Meta { fee_token: Some(fee_token), fee_payer: None, nonce: None },
                ..Default::default()
            },
            ..Default::default()
        };

        // Get nonce for fee_payer
        let fee_payer_provider = self.provider(source_chain)?;
        let fee_payer_nonce = fee_payer_request
            .get_nonce(
                fee_payer_delegation_status.stored_account(),
                &fee_payer_provider,
                &self.inner.storage,
            )
            .await?;

        // Build the fee_payer intent as a single-chain intent (not part of the merkle tree)
        let (fee_payer_asset_diffs, fee_payer_quote) = self
            .build_intent(
                &fee_payer_request,
                &fee_payer_identity,
                &fee_payer_delegation_status,
                fee_payer_nonce,
                IntentKind::Single,
                false,
            )
            .await?;

        Ok(Some((fee_payer_asset_diffs, Box::new(fee_payer_quote))))
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

        let quote_signer = self.inner.quote_signer.address();

        if chains_ok && db_ok {
            Ok(Health {
                status: "rpc ok".into(),
                version: RELAY_SHORT_VERSION.into(),
                quote_signer,
            })
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
        Ok(Self::get_keys(self, request).await?)
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
                                fiat: price,
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
                            fiat: price,
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
        self.prepare_calls_inner(request).await
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
        let (pre_call_digest, typed_data) =
            pre_call.compute_eip712_data(&self.contracts().orchestrator, chain_id)?;

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

        // compute real signature
        let intent_key = key
            .map(IntentKey::StoredKey)
            .or_else(|| {
                // Check if the signature is a normal ECDSA signature, meaning that it was signed by
                // the EOA.
                alloy::primitives::Signature::from_raw(&signature)
                    .is_ok()
                    .then_some(IntentKey::EoaRootKey)
            })
            .ok_or(IntentError::MissingKey)?;

        let key_hash = intent_key.key_hash();
        let signature = intent_key.wrap_signature(signature);

        // broadcasts intents in transactions
        let id = match context {
            PrepareCallsContext::Quote(quotes) => {
                self.send_intents(*quotes, capabilities, signature).await.inspect_err(|err| {
                    error!(
                        %err,
                        "Failed to submit call bundle transaction.",
                    );
                })?
            }
            PrepareCallsContext::PreCall(PreCallContext { mut call, chain_id }) => {
                let eoa = call.eoa;
                if eoa.is_zero() {
                    return Err(IntentError::MissingSender.into());
                }

                let provider = self.provider(chain_id)?;

                // Ensure that the key exists in the account
                match intent_key {
                    IntentKey::EoaRootKey => {
                        // If the key is the root EOA key, it always has control over the account
                    }
                    IntentKey::StoredKey(_) => {
                        let Some(key) = self
                            .get_keys_for_chain(call.eoa, chain_id)
                            .await?
                            .into_iter()
                            .find(|key| key.authorize_key.key.key_hash() == key_hash)
                        else {
                            return Err(KeysError::UnknownKeyHash(key_hash))?;
                        };

                        // We only support storing precalls signed by admin keys
                        if !key.authorize_key.key.isSuperAdmin {
                            return Err(KeysError::OnlyAdminKeyAllowed)?;
                        }
                    }
                }

                // Build the account
                let mut account = Account::new(eoa, &provider);
                if !account.is_delegated().await? {
                    let Some(stored) = self.inner.storage.read_account(&eoa).await? else {
                        return Err(StorageError::AccountDoesNotExist(eoa).into());
                    };

                    account = account.with_overrides(stored.state_overrides()?);
                }

                // Verify that signature is valid
                let orchestrator = account.get_orchestrator().await.map_err(RelayError::from)?;
                let (digest, _) = call.compute_eip712_data(
                    self.contracts().get_versioned_orchestrator(orchestrator)?,
                    chain_id,
                )?;

                if account.validate_signature(digest, signature.clone()).await? != Some(key_hash) {
                    return Err(KeysError::InvalidSignature.into());
                }

                // Store the precall
                call.signature = signature;
                self.inner.storage.store_precall(chain_id, call).await?;

                Default::default()
            }
        };

        Ok(SendPreparedCallsResponse { id })
    }

    async fn upgrade_account(&self, request: UpgradeAccountParameters) -> RpcResult<()> {
        let UpgradeAccountParameters { context, signatures } = request;
        tracing::Span::current().record("eth.chain_id", context.chain_id);

        let provider = self.provider(context.chain_id)?;

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

        if impl_addr != self.contracts().delegation_implementation() {
            return Err(AuthError::InvalidDelegation(impl_addr).into());
        }

        // Calculate precall digest.
        let (pre_call_digest, _) = storage_account
            .pre_call
            .compute_eip712_data(&self.contracts().orchestrator, context.chain_id)?;
        let (_, expected_nonce) = try_join!(
            // Ensures the initialization precall is successful.
            self.simulate_init(&storage_account, context.chain_id),
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

        let authorization = account.signed_authorization.clone();

        let data = OrchestratorContract::executePreCallsCall {
            parentEOA: address,
            preCalls: vec![account.pre_call.clone()],
        }
        .abi_encode()
        .into();

        let to = self.contracts().orchestrator();

        Ok(GetAuthorizationResponse { authorization, data, to })
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
        let signatures: Vec<Bytes> = keys
            .iter()
            .filter_map(|k| {
                k.authorize_key.key.isSuperAdmin.then_some(
                    Signature {
                        innerSignature: signature.clone(),
                        keyHash: k.authorize_key.key.key_hash(),
                        prehash: false,
                    }
                    .abi_encode_packed()
                    .into(),
                )
            })
            .collect();

        if !account.is_delegated().await? {
            let Some(stored) = self.inner.storage.read_account(&address).await? else {
                return Err(StorageError::AccountDoesNotExist(address).into());
            };

            account = account.with_overrides(stored.state_overrides()?);

            init_pre_call = Some(stored.pre_call);
        }

        let digest = account.digest_erc1271(digest);

        let results = try_join_all(
            signatures.into_iter().map(|signature| account.validate_signature(digest, signature)),
        )
        .await?;

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
    /// Returns all the shared contracts.
    pub fn contracts(&self) -> &VersionedContracts {
        &self.inner.contracts
    }

    /// Creates an escrow struct for funding intents.
    fn create_escrow_structs(
        &self,
        context: &FundingIntentContext,
    ) -> Result<Vec<Escrow>, RelayError> {
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

        context
            .assets
            .iter()
            .map(|(asset, amount)| {
                Ok(Escrow {
                    salt,
                    depositor: context.eoa,
                    recipient: self.inner.contracts.funder.address,
                    token: asset.address(),
                    settler: self.inner.chains.settler_address(context.chain_id)?,
                    sender: context.output_orchestrator,
                    settlementId: context.output_intent_digest,
                    senderChainId: U256::from(context.output_chain_id),
                    escrowAmount: *amount,
                    refundAmount: *amount,
                    refundTimestamp: refund_timestamp,
                })
            })
            .collect()
    }

    /// Builds the escrow calls based on the asset type.
    ///
    /// IMPORTANT: The escrow call is always placed last in the returned vector.
    /// This ordering is critical as it's relied upon by other parts of the system
    /// (e.g., extract_escrow_details) for efficient parsing.
    fn build_escrow_calls(&self, escrows: Vec<Escrow>) -> Vec<Call> {
        // ERC20 token: approve then escrow (escrow is last)
        let mut calls = escrows
            .iter()
            .filter(|escrow| !escrow.token.is_zero())
            .map(|escrow| Call {
                to: escrow.token,
                value: U256::ZERO,
                data: IERC20::approveCall {
                    spender: self.inner.contracts.escrow.address,
                    amount: escrow.escrowAmount,
                }
                .abi_encode()
                .into(),
            })
            .collect::<Vec<_>>();

        calls.push(Call {
            to: self.inner.contracts.escrow.address,
            // Native token: include value
            value: escrows
                .iter()
                .filter(|escrow| escrow.token.is_zero())
                .map(|escrow| escrow.escrowAmount)
                .sum(),
            data: IEscrow::escrowCall { _escrows: escrows }.abi_encode().into(),
        });

        calls
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
        intent_key: IntentKey<CallKey>,
    ) -> Result<PrepareCallsParameters, RelayError> {
        let escrows = self.create_escrow_structs(&context)?;
        let calls = self.build_escrow_calls(escrows);

        Ok(PrepareCallsParameters {
            calls,
            chain_id: context.chain_id,
            from: Some(context.eoa),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: Some(context.fee_token), nonce: None },
                revoke_keys: vec![],
                pre_calls: vec![],
                pre_call: false,
                required_funds: vec![],
            },
            state_overrides: Default::default(),
            balance_overrides: Default::default(),
            key: intent_key.into_stored_key(),
        })
    }

    /// Determines if a digest should be wrapped for ERC1271 validation.
    ///
    /// Wrapping is needed when:
    /// - It's using a KeyType::Secp256k1
    /// - The key's address derived from the public key is delegated on-chain, OR
    /// - The key has stored authorization AND the key's address matches the EOA (signing for
    ///   itself)
    /// - AND the implementation version is >= 0.5.0
    ///
    /// Returns the key address if wrapping is needed, None otherwise.
    async fn should_erc1271_wrap<P: Provider>(
        &self,
        request: &PrepareCallsParameters,
        from_delegation_status: &Option<DelegationStatus>,
        provider: &P,
    ) -> Result<Option<Address>, RelayError> {
        let Some(public_key) = request.key.as_ref().and_then(|k| k.as_secp256k1()) else {
            return Ok(None);
        };

        let key_address = Address::from_slice(&public_key[12..]);

        // If the key address matches the EOA address AND we have a delegation status, use it
        // Otherwise, fetch the delegation status for the key address
        let status = if request.from == Some(key_address) && from_delegation_status.is_some() {
            from_delegation_status.clone()
        } else {
            Account::new(key_address, provider).delegation_status(&self.inner.storage).await.ok()
        };

        // Only wrap if it's an IthacaAccount >=0.5
        let needs_wrapping = status.as_ref().is_some_and(|s| {
            if (s.is_delegated() || (s.is_stored() && request.from == Some(key_address)))
                && let Ok(impl_addr) = s.try_implementation()
            {
                return self.is_ithaca_account(impl_addr, semver::Version::new(0, 5, 0));
            }
            false
        });

        Ok(needs_wrapping.then_some(key_address))
    }
}

#[derive(Debug)]
struct IdentityParameters {
    /// Root EOA address.
    root_eoa: Address,
    /// Key
    key: IntentKey<CallKey>,
}

impl IdentityParameters {
    /// Creates a new [`IdentityParameters`] instance from the provided key.
    ///
    /// If the key is not provided, it will be derived from the root EOA address as
    /// [`KeyType::Secp256k1`] key.
    pub fn new(key: Option<&CallKey>, root_eoa: Address) -> Self {
        if let Some(key) = key {
            Self { root_eoa, key: IntentKey::StoredKey(key.clone()) }
        } else {
            Self { root_eoa, key: IntentKey::EoaRootKey }
        }
    }
}

/// Adjusts a balance based on the difference in decimals.
///
/// # Example
/// - USDC on chain A has 6 decimals, balance = 1_000_000 (represents 1 USDC)
/// - USDC on chain B has 18 decimals
/// - Result: 1_000_000_000_000_000_000 (represents 1 USDC with 18 decimals)
pub fn adjust_balance_for_decimals(balance: U256, from_decimals: u8, to_decimals: u8) -> U256 {
    let diff = (from_decimals as i32) - (to_decimals as i32);
    let factor = U256::from(10).pow(U256::from(diff.unsigned_abs()));

    if diff > 0 { balance / factor } else { balance * factor }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::U256;

    #[test]
    fn test_adjust_balance_for_decimals() {
        // Converting from 6 decimals to 18 decimals
        let balance_6_decimals = U256::from(1_000_000u64);
        let result = adjust_balance_for_decimals(balance_6_decimals, 6, 18);
        assert_eq!(result, U256::from(1_000_000_000_000_000_000u128));

        // Converting from 18 decimals to 6 decimals
        let balance_18_decimals = U256::from(1_000_000_000_000_000_000u128);
        let result = adjust_balance_for_decimals(balance_18_decimals, 18, 6);
        assert_eq!(result, U256::from(1_000_000u64));

        // Same decimals, no change
        let balance = U256::from(123_456_789u64);
        let result = adjust_balance_for_decimals(balance, 6, 6);
        assert_eq!(result, balance);
    }
}
