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
    eips::eip7702::constants::PER_AUTH_BASE_COST,
    hex,
    primitives::{fixed_bytes, map::AddressMap, Address, Bytes, TxHash, U256},
    providers::{Provider, WalletProvider},
    rpc::types::{state::AccountOverride, TransactionRequest},
    signers::Signer,
    sol_types::{SolCall, SolError, SolValue},
};
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
    error::{CallError, EstimateFeeError, SendActionError},
    price::PriceOracle,
    types::{
        executeCall, nonceSaltCall, simulateExecuteCall, Action, FeeTokens, Key, KeyType,
        PartialAction, Quote, Signature, SignedQuote, SimulationResult, UserOp, U40,
    },
    upstream::Upstream,
};

/// Ithaca `relay_` RPC namespace.
#[rpc(server, client, namespace = "relay")]
pub trait RelayApi {
    /// Get all supported fee tokens by chain.
    #[method(name = "feeTokens", aliases = ["wallet_feeTokens"])]
    async fn fee_tokens(&self) -> RpcResult<FeeTokens>;

    /// Estimates the fee a user would have to pay for the given action in the given fee token.
    #[method(name = "estimateFee", aliases = ["wallet_estimateFee"])]
    async fn estimate_fee(&self, request: PartialAction, token: Address) -> RpcResult<SignedQuote>;

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
    async fn send_action(&self, request: Action, quote: SignedQuote) -> RpcResult<TxHash>;
}

/// Implementation of the Ithaca `relay_` namespace.
#[derive(Debug)]
pub struct Relay<P, Q> {
    inner: Arc<RelayInner<P, Q>>,
}

impl<P, Q> Relay<P, Q> {
    /// Create a new Ithaca relay module.
    pub fn new(
        upstream: Upstream<P>,
        quote_signer: Q,
        quote_ttl: Duration,
        price_oracle: PriceOracle,
        fee_tokens: FeeTokens,
    ) -> Self {
        let inner = RelayInner { upstream, fee_tokens, quote_signer, quote_ttl, price_oracle };
        Self { inner: Arc::new(inner) }
    }
}

/// The EIP-7702 delegation designator.
const EIP7702_DELEGATION_DESIGNATOR: [u8; 3] = hex!("0xef0100");

/// The EIP-7702 delegation designator for a cleared delegation.
const EIP7702_CLEARED_DELEGATION: [u8; 23] =
    hex!("0xef01000000000000000000000000000000000000000000");

#[async_trait]
impl<P, Q> RelayApiServer for Relay<P, Q>
where
    P: Provider + WalletProvider + 'static,
    Q: Signer + Send + Sync + 'static,
{
    async fn fee_tokens(&self) -> RpcResult<FeeTokens> {
        Ok(self.inner.fee_tokens.clone())
    }

    async fn estimate_fee(&self, request: PartialAction, token: Address) -> RpcResult<SignedQuote> {
        let Some(token) = self.inner.fee_tokens.find(self.inner.upstream.chain_id(), &token) else {
            return Err(EstimateFeeError::UnsupportedFeeToken(token).into());
        };

        // create key
        let key = Key {
            expiry: U40::from(0),
            keyType: KeyType::Secp256k1,
            isSuperAdmin: true,
            publicKey: self.inner.quote_signer.address().abi_encode().into(),
        };

        // mocking key storage for the eoa, and the balance for the mock signer
        let overrides = AddressMap::from_iter([
            (
                self.inner.quote_signer.address(),
                AccountOverride {
                    balance: Some(U256::MAX.div_ceil(2.try_into().unwrap())),
                    ..Default::default()
                },
            ),
            (
                request.op.eoa,
                AccountOverride {
                    state_diff: Some(key.storage_slots()),
                    // we manually etch the 7702 designator since we do not have a signed auth item
                    code: request.auth.map(|addr| {
                        Bytes::from([&EIP7702_DELEGATION_DESIGNATOR, addr.as_slice()].concat())
                    }),
                    ..Default::default()
                },
            ),
        ]);

        // fill userop
        let mut op = UserOp {
            eoa: request.op.eoa,
            executionData: request.op.executionData.clone(),
            nonce: request.op.nonce,
            payer: Address::ZERO,
            paymentToken: token.address,
            paymentRecipient: Address::ZERO,
            paymentAmount: U256::ZERO,
            paymentMaxAmount: U256::ZERO,
            paymentPerGas: U256::ZERO,
            // we intentionally do not use the maximum amount of gas since the contracts add a small
            // overhead when checking if there is sufficient gas for the op
            combinedGas: U256::from(20_000_000),
            signature: Bytes::default(),
        };

        // sign userop
        debug!(eoa = %request.op.eoa, "Retrieving nonce salt");
        let nonce_salt = self
            .inner
            .upstream
            .call_with_overrides::<nonceSaltCall>(
                &TransactionRequest {
                    to: Some(request.op.eoa.into()),
                    input: nonceSaltCall {}.abi_encode().into(),
                    ..Default::default()
                },
                &overrides,
            )
            .await
            .map_or(U256::ZERO, |ret| ret._0);
        debug!(eoa = %request.op.eoa, "Got nonce salt {nonce_salt}");
        let inner_signature = self
            .inner
            .quote_signer
            .sign_hash(
                &op.eip712_digest(
                    self.inner.upstream.entrypoint(),
                    self.inner.upstream.chain_id(),
                    nonce_salt,
                )
                .map_err(|err| EstimateFeeError::InternalError(err.into()))?,
            )
            .await
            .map_err(|err| EstimateFeeError::InternalError(err.into()))?;
        op.signature = Signature {
            innerSignature: inner_signature.as_bytes().into(), // (r, s, v + 27)
            keyHash: key.key_hash(),
            prehash: false,
        }
        .abi_encode_packed()
        .into();

        // we perform a call to `simulateExecute`, which reverts with the amount of gas used and an
        // error selector.
        let mut gas_estimate = match self
            .inner
            .upstream
            .call_with_overrides::<simulateExecuteCall>(
                &TransactionRequest {
                    from: Some(self.inner.quote_signer.address()),
                    to: Some(self.inner.upstream.entrypoint().into()),
                    input: simulateExecuteCall { encodedUserOp: op.abi_encode().into() }
                        .abi_encode()
                        .into(),
                    ..Default::default()
                },
                &overrides,
            )
            .await
        {
            Err(CallError::RpcError(alloy::transports::RpcError::ErrorResp(err))) => {
                let data = err.as_revert_data().unwrap_or_default();
                if let Ok(result) = SimulationResult::abi_decode(&data, false) {
                    if result.err != fixed_bytes!("00000000") {
                        return Err(EstimateFeeError::OpRevert {
                            revert_reason: result.err.into(),
                        }
                        .into());
                    }

                    result.gUsed.to::<u64>()
                } else {
                    return Err(EstimateFeeError::OpRevert { revert_reason: data }.into());
                }
            }
            _ => return Err(EstimateFeeError::SimulationError.into()),
        };
        let native_fee_estimate =
            self.inner.upstream.estimate_eip1559().await.map_err(EstimateFeeError::from)?;

        // for 7702 designations there is an additional gas charge
        //
        // note: this is not entirely accurate, as there is also a gas refund in 7702, but at this
        // point it is not possible to compute the gas refund, so it is an overestimate, as we also
        // need to charge for the account being presumed empty.
        if request.auth.is_some() {
            gas_estimate += PER_AUTH_BASE_COST + 25000;
        }
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
        };
        let sig = self
            .inner
            .quote_signer
            .sign_hash(&quote.digest())
            .await
            .map_err(|err| EstimateFeeError::InternalError(err.into()))?;

        Ok(quote.into_signed(sig))
    }

    // todo: chain ids
    async fn send_action(&self, action: Action, quote: SignedQuote) -> RpcResult<TxHash> {
        // verify payment recipient is entrypoint or us
        if !action.op.paymentRecipient.is_zero()
            && action.op.paymentRecipient != self.inner.upstream.default_signer_address()
        {
            return Err(SendActionError::WrongPaymentRecipient.into());
        }

        let mut request = TransactionRequest {
            input: executeCall { encodedUserOp: action.op.abi_encode().into() }.abi_encode().into(),
            to: Some(self.inner.upstream.entrypoint().into()),
            // note: we also set the `from` field here to correctly estimate for contracts that use
            // e.g. `tx.origin`
            from: Some(self.inner.upstream.default_signer_address()),
            chain_id: Some(self.inner.upstream.chain_id()),
            // setting the gas limit here to exactly the gas estimate makes the tx revert;
            // otoh setting it way higher is wasteful, as the estimate is actually very accurate.
            // gas: Some(quote.ty().gas_estimate + ENTRYPOINT_INNER_GAS_OVERHEAD),
            max_fee_per_gas: Some(quote.ty().native_fee_estimate.max_fee_per_gas),
            max_priority_fee_per_gas: Some(quote.ty().native_fee_estimate.max_priority_fee_per_gas),
            ..Default::default()
        };

        if let Some(auth) = action.auth {
            // todo: persist auth
            if !auth.inner().chain_id().is_zero() {
                return Err(SendActionError::AuthItemNotChainAgnostic.into());
            }
            request.authorization_list = Some(vec![auth]);
        } else {
            let code =
                self.inner.upstream.get_code(action.op.eoa).await.map_err(SendActionError::from)?;

            if code.get(..3) != Some(&EIP7702_DELEGATION_DESIGNATOR[..])
                || code[..] == EIP7702_CLEARED_DELEGATION
            {
                return Err(SendActionError::EoaNotDelegated(action.op.eoa).into());
            }
        }

        // check that the payment amount matches whats in the quote
        if quote.ty().amount != action.op.paymentAmount {
            return Err(SendActionError::InvalidFeeAmount {
                expected: quote.ty().amount,
                got: action.op.paymentAmount,
            }
            .into());
        }

        // check that digest of the userop is the same as in the quote
        if quote.ty().digest != action.op.digest() {
            return Err(SendActionError::InvalidOpDigest {
                expected: quote.ty().digest,
                got: action.op.digest(),
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

        // broadcast the tx
        Ok(self
            .inner
            .upstream
            .sign_and_send(request)
            .await
            .inspect_err(
                |err| warn!(target: "rpc::wallet", ?err, "Error adding sponsored tx to pool"),
            )
            .map_err(SendActionError::from)?)
    }
}

/// Implementation of the Ithaca `relay_` namespace.
#[derive(Debug)]
struct RelayInner<P, Q> {
    /// The upstream RPC of the relay.
    upstream: Upstream<P>,
    /// Supported fee tokens.
    fee_tokens: FeeTokens,
    /// The signer used to sign quotes.
    quote_signer: Q,
    /// The TTL of a quote.
    quote_ttl: Duration,
    /// Price oracle.
    price_oracle: PriceOracle,
}
