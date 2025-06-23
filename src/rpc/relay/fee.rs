use crate::{
    chains::Chain,
    error::{KeysError, QuoteError, RelayError},
    provider::ProviderExt,
    rpc::relay::manager::Manager,
    types::{
        Account, AssetDiffs, GasEstimate, Intent, IntentKind, Key, KeyWith712Signer, Orchestrator,
        OrchestratorContract, PartialAction, Quote, Signature, SignedCalls, Transfer,
    },
};
use alloy::{
    consensus::{SignableTransaction, TxEip1559},
    eips::eip7702::constants::EIP7702_DELEGATION_DESIGNATOR,
    primitives::{Address, Bytes, U256, bytes},
    providers::{
        Provider,
        utils::{EIP1559_FEE_ESTIMATION_PAST_BLOCKS, Eip1559Estimator},
    },
    rpc::types::state::{AccountOverride, StateOverridesBuilder},
    sol_types::{SolCall, SolValue},
};
use futures_util::{TryFutureExt, future::try_join4};
use tracing::{debug, instrument};

#[async_trait::async_trait]
pub trait FeeEstimator: Manager {
    /// Estimate fees for executing actions
    #[instrument(skip_all)]
    async fn estimate_fee(
        &self,
        request: PartialAction,
        token: Address,
        authorization_address: Option<Address>,
        account_key: Key,
        key_slot_override: bool,
        intent_kind: IntentKind,
    ) -> Result<(AssetDiffs, Quote), RelayError> {
        let chain = self
            .chains()
            .get(request.chain_id)
            .ok_or(RelayError::UnsupportedChain(request.chain_id))?;

        let provider = chain.provider.clone();
        let Some(token) = self.fee_tokens().find(request.chain_id, &token) else {
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
                    &[self.priority_fee_percentile()],
                )
                .map_err(RelayError::from),
            // fetch price in eth
            async {
                // TODO: only handles eth as native fee token
                Ok(self.price_oracle().eth_price(token.kind).await)
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
        let payment_per_gas = if intent_kind.is_single() {
            (native_fee_estimate.max_fee_per_gas as f64 * 10u128.pow(token.decimals as u32) as f64)
                / f64::from(eth_price)
        } else {
            // todo: is_multi_input should take a fee as well eventually
            0f64
        };

        // fill intent
        let mut intent = Intent {
            eoa: request.intent.eoa,
            executionData: request.intent.execution_data.clone(),
            nonce: request.intent.nonce,
            payer: request.intent.payer.unwrap_or_default(),
            paymentToken: token.address,
            paymentRecipient: self.fee_recipient(),
            supportedAccountImplementation: delegation,
            encodedPreCalls: request
                .intent
                .pre_calls
                .into_iter()
                .map(|pre_call| pre_call.abi_encode().into())
                .collect(),
            encodedFundTransfers: request
                .intent
                .fund_transfers
                .into_iter()
                .map(|(token, amount)| Transfer { token, amount }.abi_encode().into())
                .collect(),
            ..Default::default()
        };

        let extra_payment = self.estimate_extra_fee(&chain, &intent).await?
            * U256::from(10u128.pow(token.decimals as u32))
            / eth_price;

        let intrinsic_gas = approx_intrinsic_cost(
            &OrchestratorContract::executeCall {
                isMultiChain: !intent_kind.is_single(),
                encodedIntent: intent.abi_encode().into(),
            }
            .abi_encode(),
            authorization_address.is_some(),
        );

        let initial_payment = U256::from(intrinsic_gas as f64 * payment_per_gas) + extra_payment;

        intent.set_legacy_payment_amount(initial_payment);

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

        if !intent.encodedFundTransfers.is_empty() {
            // todo: the contract version is broken, and any signature will pass.
            intent.funder = self.contracts().funder.address;
        }

        // todo: simulate with executeMultiChain if intent.is_multichain
        // we estimate gas and fees
        let (asset_diff, sim_result) = orchestrator
            .simulate_execute(
                self.simulator(),
                &intent,
                account_key.keyType,
                payment_per_gas,
                self.asset_info().clone(),
            )
            .await?;

        // todo: re-evaluate if this is still necessary
        let gas_estimate = GasEstimate::from_combined_gas(
            sim_result.gCombined.to(),
            intrinsic_gas,
            self.quote_config(),
        );

        debug!(eoa = %request.intent.eoa, gas_estimate = ?gas_estimate, "Estimated intent");

        // Fill combinedGas and empty dummy signature
        intent.combinedGas = U256::from(gas_estimate.intent);
        intent.signature = bytes!("");
        intent.funderSignature = bytes!("");

        // Calculate amount with updated paymentPerGas
        if !intent_kind.is_single() {
            // todo: temporary
            intent.set_legacy_payment_amount(U256::ZERO);
        } else {
            intent.set_legacy_payment_amount(
                extra_payment + U256::from((payment_per_gas * gas_estimate.tx as f64).ceil()),
            )
        }

        let quote = Quote {
            chain_id: request.chain_id,
            payment_token_decimals: token.decimals,
            output: intent,
            extra_payment,
            eth_price,
            tx_gas: gas_estimate.tx,
            native_fee_estimate,
            authorization_address,
            orchestrator: *orchestrator.address(),
            is_multi_chain: !intent_kind.is_single(),
        };

        Ok((asset_diff, quote))
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
                input: intent.encode_execute(false),
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
}

/// Approximates the intrinsic cost of a transaction.
///
/// This function assumes Prague rules.
fn approx_intrinsic_cost(input: &[u8], has_auth: bool) -> u64 {
    use alloy::eips::eip7702::constants::PER_EMPTY_ACCOUNT_COST;

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
