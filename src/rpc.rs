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
    eips::{
        eip7702::{
            constants::{PER_AUTH_BASE_COST, PER_EMPTY_ACCOUNT_COST},
            SignedAuthorization,
        },
        Encodable2718,
    },
    network::{
        Ethereum, EthereumWallet, NetworkWallet, TransactionBuilder, TransactionBuilder7702,
    },
    primitives::{map::AddressMap, Address, Bytes, TxHash, U256},
    providers::{fillers::NonceManager, Provider},
    rpc::types::{state::AccountOverride, TransactionRequest},
    sol_types::{SolCall, SolStruct, SolValue},
    transports::TransportErrorKind,
};
use futures_util::TryFutureExt;
use jsonrpsee::{
    core::{async_trait, RpcResult},
    proc_macros::rpc,
};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tracing::{debug, warn};

use crate::{
    chains::Chains,
    constants::{
        EIP7702_CLEARED_DELEGATION, EIP7702_DELEGATION_DESIGNATOR, INNER_ENTRYPOINT_GAS_OVERHEAD,
        TX_GAS_BUFFER, USER_OP_GAS_BUFFER,
    },
    error::{EstimateFeeError, SendActionError},
    nonce::MultiChainNonceManager,
    price::PriceOracle,
    signers::DynSigner,
    types::{
        Account, Action, Entry, EntryPoint, FeeTokens, KeyType, KeyWith712Signer, PartialAction,
        Quote, Signature, SignedQuote, UserOp, ENTRYPOINT_NO_ERROR,
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
}

/// Implementation of the Ithaca `relay_` namespace.
#[derive(Debug)]
pub struct Relay {
    inner: Arc<RelayInner>,
}

impl Relay {
    /// Create a new Ithaca relay module.
    pub fn new(
        chains: Chains,
        tx_signer: EthereumWallet,
        quote_signer: DynSigner,
        quote_ttl: Duration,
        price_oracle: PriceOracle,
        fee_tokens: FeeTokens,
    ) -> Self {
        let inner = RelayInner {
            chains,
            fee_tokens,
            nonce_manager: MultiChainNonceManager::default(),
            tx_signer,
            quote_signer,
            quote_ttl,
            price_oracle,
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
            .ok_or(EstimateFeeError::UnsupportedChain(request.chain_id))?;
        let Some(token) = self.inner.fee_tokens.find(request.chain_id, &token) else {
            return Err(EstimateFeeError::UnsupportedFeeToken(token).into());
        };

        // create key
        let mock_signer_address = self.inner.quote_signer.address();
        let key_with_signer = KeyWith712Signer::random(key_type)
            .and_then(|k| k.ok_or_else(|| EstimateFeeError::UnsupportedKeyType.into()))
            .map_err(EstimateFeeError::from)?;

        // mocking key storage for the eoa, and the balance for the mock signer
        let overrides = AddressMap::from_iter([
            (
                mock_signer_address,
                AccountOverride::default().with_balance(U256::MAX.div_ceil(2.try_into().unwrap())),
            ),
            (
                request.op.eoa,
                // todo: we can't use builder api here because we only maybe set the code sometimes https://github.com/alloy-rs/alloy/issues/2062
                AccountOverride {
                    state_diff: Some(key_with_signer.key.storage_slots()),
                    // we manually etch the 7702 designator since we do not have a signed auth item
                    code: authorization_address.map(|addr| {
                        Bytes::from([&EIP7702_DELEGATION_DESIGNATOR, addr.as_slice()].concat())
                    }),
                    ..Default::default()
                },
            ),
        ]);

        // load account and entrypoint
        let account =
            Account::new(request.op.eoa, provider.clone()).with_overrides(overrides.clone());
        let (entrypoint_address, nonce_salt) =
            futures_util::try_join!(account.entrypoint(), account.nonce_salt())
                .map_err(EstimateFeeError::from)?;
        let entrypoint =
            Entry::new(entrypoint_address, provider.clone()).with_overrides(overrides.clone());

        // fill userop
        let mut op = UserOp {
            eoa: request.op.eoa,
            executionData: request.op.executionData.clone(),
            nonce: request.op.nonce,
            paymentToken: token.address,
            // we intentionally do not use the maximum amount of gas since the contracts add a small
            // overhead when checking if there is sufficient gas for the op
            combinedGas: U256::from(20_000_000),
            ..Default::default()
        };

        // sign userop
        let payload =
            op.as_eip712(nonce_salt).map_err(|err| EstimateFeeError::InternalError(err.into()))?;
        let signature = key_with_signer
            .signer
            .sign_payload_hash(
                payload.eip712_signing_hash(
                    &entrypoint
                        .eip712_domain(op.is_multichain())
                        .await
                        .map_err(EstimateFeeError::from)?,
                ),
            )
            .await
            .map_err(EstimateFeeError::InternalError)?;

        op.signature = Signature {
            innerSignature: signature,
            keyHash: key_with_signer.key.key_hash(),
            prehash: false,
        }
        .abi_encode_packed()
        .into();

        // we estimate gas and fees
        let (mut gas_estimate, native_fee_estimate) = futures_util::try_join!(
            entrypoint
                .simulate_execute(&op)
                .map_ok(|gas| gas.to::<u64>())
                .map_err(EstimateFeeError::from),
            provider.estimate_eip1559_fees(None).map_err(EstimateFeeError::from)
        )?;

        // for 7702 designations there is an additional gas charge
        //
        // note: this is not entirely accurate, as there is also a gas refund in 7702, but at this
        // point it is not possible to compute the gas refund, so it is an overestimate, as we also
        // need to charge for the account being presumed empty.
        if authorization_address.is_some() {
            gas_estimate += PER_AUTH_BASE_COST + PER_EMPTY_ACCOUNT_COST;
        }

        // Add some leeway, since the actual simulation may no be enough.
        gas_estimate += USER_OP_GAS_BUFFER;
        debug!(eoa = %request.op.eoa, gas_estimate = %gas_estimate, "Estimated operation");

        // Get paymentPerGas
        // TODO: only handles eth as native fee token
        let Some(eth_price) = self.inner.price_oracle.eth_price(token.coin).await else {
            return Err(EstimateFeeError::UnavailablePrice(token.address).into());
        };
        let gas_price = U256::from(
            native_fee_estimate.max_fee_per_gas + native_fee_estimate.max_priority_fee_per_gas,
        );
        op.paymentPerGas = (gas_price * U256::from(10u128.pow(token.decimals as u32))) / eth_price;

        // Calculate amount with updated paymentPerGas
        op.paymentAmount = op.paymentPerGas * op.combinedGas;
        op.paymentMaxAmount = op.paymentAmount;

        // todo: this is just a mock, we should add actual amounts
        let quote = Quote {
            token: token.address,
            amount: op.paymentPerGas * U256::from(gas_estimate),
            gas_estimate,
            native_fee_estimate,
            digest: op.digest(),
            ttl: SystemTime::now()
                .checked_add(self.inner.quote_ttl)
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
        let provider = self
            .inner
            .chains
            .get(request.chain_id)
            .ok_or(EstimateFeeError::UnsupportedChain(request.chain_id))?;

        // verify payment recipient is entrypoint or us
        let tx_signer_address = <EthereumWallet as NetworkWallet<Ethereum>>::default_signer_address(
            &self.inner.tx_signer,
        );
        if !request.op.paymentRecipient.is_zero()
            && request.op.paymentRecipient != tx_signer_address
        {
            return Err(SendActionError::WrongPaymentRecipient.into());
        }

        // possibly mocking the code for the eoa
        let overrides = AddressMap::from_iter([(
            request.op.eoa,
            AccountOverride {
                // we manually etch the 7702 designator since we do not have a signed auth item
                code: authorization.as_ref().map(|auth| {
                    Bytes::from([&EIP7702_DELEGATION_DESIGNATOR, auth.address.as_slice()].concat())
                }),
                ..Default::default()
            },
        )]);

        // get the account and entrypoint
        let account = Account::new(request.op.eoa, provider.clone()).with_overrides(overrides);
        let entrypoint =
            account.entrypoint().await.map_err(|err| SendActionError::InternalError(err.into()))?;

        // Calculate tx.gas with the 63/64 check, auth cost and extra for leeway.
        let mut tx_gas =
            TX_GAS_BUFFER + ((quote.ty().gas_estimate + INNER_ENTRYPOINT_GAS_OVERHEAD) * 64) / 63;
        if authorization.is_some() {
            tx_gas += PER_AUTH_BASE_COST + PER_EMPTY_ACCOUNT_COST;
        }

        let mut tx = TransactionRequest::default()
            .with_chain_id(request.chain_id)
            .input(
                EntryPoint::executeCall { encodedUserOp: request.op.abi_encode().into() }
                    .abi_encode()
                    .into(),
            )
            .to(entrypoint)
            .from(tx_signer_address)
            .gas_limit(tx_gas)
            .max_fee_per_gas(quote.ty().native_fee_estimate.max_fee_per_gas)
            .max_priority_fee_per_gas(quote.ty().native_fee_estimate.max_priority_fee_per_gas);

        // check that the authorization item matches what's in the quote
        if quote.ty().authorization_address != authorization.as_ref().map(|auth| auth.address) {
            return Err(SendActionError::InvalidAuthItem {
                expected: quote.ty().authorization_address,
                got: authorization.map(|auth| auth.address),
            }
            .into());
        }

        if let Some(auth) = authorization {
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

            tx.set_authorization_list(vec![auth]);
        } else {
            let code = provider.get_code_at(request.op.eoa).await.map_err(SendActionError::from)?;

            if code.get(..3) != Some(&EIP7702_DELEGATION_DESIGNATOR[..])
                || code[..] == EIP7702_CLEARED_DELEGATION
            {
                return Err(SendActionError::EoaNotDelegated(request.op.eoa).into());
            }
        }

        // check that the payment amount matches whats in the quote
        if quote.ty().amount != request.op.paymentAmount {
            return Err(SendActionError::InvalidFeeAmount {
                expected: quote.ty().amount,
                got: request.op.paymentAmount,
            }
            .into());
        }

        // check that digest of the userop is the same as in the quote
        if quote.ty().digest != request.op.digest() {
            return Err(SendActionError::InvalidOpDigest {
                expected: quote.ty().digest,
                got: request.op.digest(),
            }
            .into());
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

        // try eth_call before committing to send the actual transaction
        provider
            .call(&tx)
            .await
            .and_then(|res| {
                EntryPoint::executeCall::abi_decode_returns(&res, true)
                    .map_err(TransportErrorKind::custom)
            })
            .map_err(SendActionError::from)
            .and_then(|result| {
                if result.err != ENTRYPOINT_NO_ERROR {
                    return Err(SendActionError::OpRevert { revert_reason: result.err.into() });
                }
                Ok(())
            })?;

        // broadcast the tx
        tx.set_nonce(
            self.inner
                .nonce_manager
                .get_next_nonce(&provider, tx_signer_address)
                .await
                .map_err(|err| SendActionError::InternalError(err.into()))?,
        );
        Ok(provider
            .send_raw_transaction(
                &tx.build(&self.inner.tx_signer)
                    .await
                    .map_err(|err| SendActionError::InternalError(err.into()))?
                    .encoded_2718(),
            )
            .await
            .map(|pending| *pending.tx_hash())
            .inspect_err(|err| warn!(?err, "Error adding sponsored tx to pool"))
            .map_err(SendActionError::from)?)
    }
}

/// Implementation of the Ithaca `relay_` namespace.
#[derive(Debug)]
struct RelayInner {
    /// The chains supported by the relay.
    chains: Chains,
    /// Supported fee tokens.
    fee_tokens: FeeTokens,
    /// The nonce manager used to manage transaction nonces.
    nonce_manager: MultiChainNonceManager,
    /// The signer used to sign transactions.
    tx_signer: EthereumWallet,
    /// The signer used to sign quotes.
    quote_signer: DynSigner,
    /// The TTL of a quote.
    quote_ttl: Duration,
    /// Price oracle.
    price_oracle: PriceOracle,
}
