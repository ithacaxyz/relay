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
    error::{AuthError, IntentError, KeysError, QuoteError, RelayError, StorageError},
    rpc::{Relay, relay::manager::Manager},
    storage::StorageApi,
    transactions::TransactionStatus,
    types::{
        Account, AssetMetadata, AssetType, CreatableAccount, IERC20, MULTICHAIN_NONCE_PREFIX,
        OrchestratorContract::IntentExecuted,
        Signature, SignedCall, SignedCalls,
        rpc::{
            AddressOrNative, Asset7811, AssetFilterItem, AuthorizeKeyResponse, BundleId,
            CallReceipt, CallStatusCode, CallsStatus, ChainCapabilities, ChainFees,
            GetAssetsParameters, GetAssetsResponse, GetKeysParameters, PrepareCallsParameters,
            PrepareCallsResponse, PrepareUpgradeAccountParameters, PrepareUpgradeAccountResponse,
            RelayCapabilities, SendPreparedCallsParameters, SendPreparedCallsResponse,
            UpgradeAccountContext, UpgradeAccountDigests, UpgradeAccountParameters,
            ValidSignatureProof, VerifySignatureParameters, VerifySignatureResponse,
        },
    },
    version::RELAY_SHORT_VERSION,
};
use alloy::{
    eips::eip7702::constants::EIP7702_DELEGATION_DESIGNATOR,
    primitives::{Address, B256, Bytes, ChainId, U256},
    providers::Provider,
    rpc::types::{
        Authorization,
        state::{AccountOverride, StateOverridesBuilder},
    },
    sol_types::SolValue,
};
use futures_util::future::try_join_all;
use jsonrpsee::{
    core::{RpcResult, async_trait},
    proc_macros::rpc,
};
use tokio::try_join;
use tracing::error;

/// Ithaca `relay_` RPC namespace.
#[rpc(server, client, namespace = "wallet")]
pub trait RelayApi {
    /// Checks the health of the relay and returns its version.
    #[method(name = "health", aliases = ["health"])]
    async fn health(&self) -> RpcResult<String>;

    /// Get capabilities of the relay, which are different sets of configuration values.
    #[method(name = "getCapabilities")]
    async fn get_capabilities(&self, chains: Vec<ChainId>) -> RpcResult<RelayCapabilities>;

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

#[async_trait]
impl RelayApiServer for Relay {
    async fn health(&self) -> RpcResult<String> {
        let providers = self
            .inner
            .chains
            .chain_ids_iter()
            .map(|chain_id| self.provider(*chain_id))
            .collect::<Result<Vec<_>, RelayError>>()?;
        let chains_ok =
            try_join_all(providers.into_iter().map(|provider| provider.get_block_number()))
                .await
                .is_ok();
        let db_ok = self.inner.storage.ping().await.is_ok();

        if chains_ok && db_ok {
            Ok(RELAY_SHORT_VERSION.to_string())
        } else {
            Err(RelayError::Unhealthy.into())
        }
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

                if request.asset_type_filter.is_empty()
                    || request.asset_type_filter.contains(&AssetType::ERC20)
                {
                    if let Some(tokens) = self.inner.fee_tokens.chain_tokens(chain) {
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

        let receipts = tx_statuses
            .iter()
            .flatten()
            .filter_map(|(chain_id, status)| match status {
                TransactionStatus::Confirmed(receipt) => Some((*chain_id, receipt.clone())),
                _ => None,
            })
            .collect::<Vec<_>>();

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
