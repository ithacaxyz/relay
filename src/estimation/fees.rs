//! Fee calculation engine for intent pricing.
//!
//! This module handles:
//! - Gas price estimation
//! - L1 data availability fees
//! - Token price conversions
//! - Payment amount calculation

use crate::{
    asset::AssetInfoServiceHandle,
    chains::{Chain, Chains},
    config::QuoteConfig,
    constants::{COLD_SSTORE_GAS_BUFFER, P256_GAS_BUFFER},
    error::{KeysError, QuoteError, RelayError},
    price::PriceOracle,
    provider::ProviderExt,
    rpc::{Relay, RelayApiServer},
    types::{
        Account, ChainAssetDiffs, FeeEstimationContext, FeeTokens, GasEstimate, Intent, IntentKind,
        KeyWith712Signer, Orchestrator, PartialIntent, Quote, Signature, SignedCalls, Transfer,
        VersionedContracts,
        rpc::{AssetFilterItem, GetAssetsParameters},
    },
};
use alloy::{
    consensus::{TxEip1559, TxEip7702},
    eips::{
        eip1559::Eip1559Estimation,
        eip7702::{SignedAuthorization, constants::PER_EMPTY_ACCOUNT_COST},
    },
    primitives::{Address, ChainId, U256, bytes},
    providers::{
        Provider,
        utils::{EIP1559_FEE_ESTIMATION_PAST_BLOCKS, Eip1559Estimator},
    },
    rlp::Encodable,
    sol_types::SolValue,
};
use futures_util::TryFutureExt;
use std::sync::Arc;
use tokio::try_join;
use tracing::{debug, instrument};

use super::build_simulation_overrides;

/// Dependencies required for fee estimation.
///
/// This struct contains all the external dependencies that the fee estimation
/// functions need to operate.
#[derive(Debug)]
pub struct EstimationDependencies<'a> {
    /// Contract addresses
    pub contracts: &'a VersionedContracts,
    /// Supported chains
    pub chains: &'a Chains,
    /// Fee tokens configuration
    pub fee_tokens: &'a Arc<FeeTokens>,
    /// Fee recipient address
    pub fee_recipient: Address,
    /// Quote configuration
    pub quote_config: &'a QuoteConfig,
    /// Price oracle for token conversions
    pub price_oracle: &'a PriceOracle,
    /// Asset info service
    pub asset_info: &'a AssetInfoServiceHandle,
    /// Priority fee percentile
    pub priority_fee_percentile: f64,
    /// Relay instance for accessing specific methods
    pub relay: &'a Relay,
}

impl<'a> EstimationDependencies<'a> {
    /// Create a new EstimationDependencies from individual components.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        contracts: &'a VersionedContracts,
        chains: &'a Chains,
        fee_tokens: &'a Arc<FeeTokens>,
        fee_recipient: Address,
        quote_config: &'a QuoteConfig,
        price_oracle: &'a PriceOracle,
        asset_info: &'a AssetInfoServiceHandle,
        priority_fee_percentile: f64,
        relay: &'a Relay,
    ) -> Self {
        Self {
            contracts,
            chains,
            fee_tokens,
            fee_recipient,
            quote_config,
            price_oracle,
            asset_info,
            priority_fee_percentile,
            relay,
        }
    }
}

/// Approximates the intrinsic gas cost for a transaction.
///
/// This function calculates the base cost of a transaction including:
/// - Base transaction cost (21000 gas)
/// - Calldata cost (16 gas per byte, regardless of value)
/// - Optional EIP-7702 authorization cost
///
/// # Returns
/// The estimated intrinsic gas cost in gas units
///
/// # Note
/// This is an overestimate as it doesn't account for gas refunds in EIP-7702,
/// and assumes all calldata bytes cost 16 gas (actual cost is 4 for zero bytes on Ethereum).
pub fn approx_intrinsic_cost(input: &[u8], has_auth: bool) -> u64 {
    // for 7702 designations there is an additional gas charge
    //
    // note: this is not entirely accurate, as there is also a gas refund in 7702, but at this
    // point it is not possible to compute the gas refund, so it is an overestimate, as we also
    // need to charge for the account being presumed empty.
    let auth_cost = if has_auth { PER_EMPTY_ACCOUNT_COST } else { 0 };

    // We just assume gas cost to cost 16 gas per token to eliminate fluctuations in gas estimates
    // due to calldata values changing. A more robust approach here is either only doing an
    // upperbound for calldata ranges that will change and doing a more accurate estimate for
    // calldata ranges we know to be fixed (e.g. the EOA address), or just sending the calldata to
    // an empty address on the chain the intent is for to get an estimate of the calldata.
    21000 + auth_cost + input.len() as u64 * 16
}

/// Estimates additional fees to be paid for a intent (e.g the current L1 DA fees).
///
/// ## Opstack
///
/// The fee is impacted by the L1 Base fee and the blob base fee.
///
/// Returns fees in ETH.
#[instrument(skip_all)]
pub async fn estimate_extra_fee(
    chain: &Chain,
    intent: &Intent,
    auth: Option<SignedAuthorization>,
    fees: &Eip1559Estimation,
    gas_estimate: &GasEstimate,
    orchestrator_address: Address,
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
                to: orchestrator_address,
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
                to: orchestrator_address.into(),
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

/// Main fee estimation function that calculates quotes for intents.
///
/// This function handles the complete fee estimation process including:
/// - Fetching asset balances and chain fee history
/// - Building state overrides for simulation
/// - Simulating intent execution
/// - Calculating gas costs and payment amounts
/// - Building complete quotes with all pricing information
#[instrument(skip_all)]
pub async fn estimate_fee(
    deps: &EstimationDependencies<'_>,
    intent: PartialIntent,
    chain_id: ChainId,
    prehash: bool,
    context: FeeEstimationContext,
) -> Result<(ChainAssetDiffs, Quote), RelayError> {
    let chain = deps.chains.get(chain_id).ok_or(RelayError::UnsupportedChain(chain_id))?;

    let provider = chain.provider.clone();
    let Some(token) = deps.fee_tokens.find(chain_id, &context.fee_token) else {
        return Err(QuoteError::UnsupportedFeeToken(context.fee_token).into());
    };

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
            deps.relay
                .get_assets(GetAssetsParameters {
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
                    &[deps.priority_fee_percentile],
                )
                .await
                .map_err(RelayError::from)
        },
        // Fetch ETH price
        async {
            // TODO: only handles eth as native fee token
            Ok(deps.price_oracle.eth_price(token.kind).await)
        }
    )?;

    let fee_token_balance = assets_response.balance_on_chain(chain_id, context.fee_token.into());

    // Build state overrides for simulation
    let overrides =
        build_simulation_overrides(&intent, &context, mock_from, fee_token_balance, &provider)
            .await?
            .build();
    let account = Account::new(intent.eoa, &provider).with_overrides(overrides.clone());

    // Fetch orchestrator and delegation in parallel
    let (orchestrator, delegation) = try_join!(
        // Fetch orchestrator from the account and ensure it is supported
        async {
            let orchestrator_addr = account.get_orchestrator().await?;
            if !deps.relay.is_supported_orchestrator(&orchestrator_addr) {
                return Err(RelayError::UnsupportedOrchestrator(orchestrator_addr));
            }
            Ok(Orchestrator::new(orchestrator_addr, &provider).with_overrides(overrides))
        },
        // Fetch delegation from the account and ensure it is supported
        deps.relay.has_supported_delegation(&account).map_err(RelayError::from)
    )?;

    debug!(
        %chain_id,
        fee_token = ?token,
        ?fee_history,
        ?eth_price,
        "Got fee parameters"
    );

    let native_fee_estimate = Eip1559Estimator::default().estimate(
        fee_history.latest_block_base_fee().unwrap_or_default(),
        &fee_history.reward.unwrap_or_default(),
    );

    let Some(eth_price) = eth_price else {
        return Err(QuoteError::UnavailablePrice(token.address).into());
    };
    let payment_per_gas = (native_fee_estimate.max_fee_per_gas as f64
        * 10u128.pow(token.decimals as u32) as f64)
        / f64::from(eth_price);

    // fill intent
    let mut intent_to_sign = Intent {
        eoa: intent.eoa,
        executionData: intent.execution_data.clone(),
        nonce: intent.nonce,
        payer: intent.payer.unwrap_or_default(),
        paymentToken: token.address,
        paymentRecipient: deps.fee_recipient,
        supportedAccountImplementation: delegation,
        encodedPreCalls: intent
            .pre_calls
            .into_iter()
            .map(|pre_call| pre_call.abi_encode().into())
            .collect(),
        encodedFundTransfers: intent
            .fund_transfers
            .into_iter()
            .map(|(token, amount)| Transfer { token, amount }.abi_encode().into())
            .collect(),
        isMultichain: !context.intent_kind.is_single(),
        ..Default::default()
    };

    // For MultiOutput intents, set the settler address and context
    if let IntentKind::MultiOutput { settler_context, .. } = &context.intent_kind {
        let interop = deps.chains.interop().ok_or(QuoteError::MultichainDisabled)?;
        intent_to_sign.settler = interop.settler_address();
        intent_to_sign.settlerContext = settler_context.clone();
    }

    if intent_to_sign.isMultichain {
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
            .sign_typed_data(
                &intent_to_sign.as_eip712().map_err(RelayError::from)?,
                &orchestrator
                    .eip712_domain(intent_to_sign.is_multichain())
                    .await
                    .map_err(RelayError::from)?,
            )
            .await
            .map_err(RelayError::from)?;

        intent_to_sign.signature = Signature {
            innerSignature: signature,
            keyHash: context.account_key.key_hash(),
            prehash,
        }
        .abi_encode_packed()
        .into();
    }

    if !intent_to_sign.encodedFundTransfers.is_empty() {
        intent_to_sign.funder = deps.contracts.funder.address;
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
    intent_to_sign.set_legacy_payment_amount(U256::from(1));

    let (asset_diffs, sim_result) = orchestrator
        .simulate_execute(
            mock_from,
            deps.contracts.simulator.address,
            &intent_to_sign,
            deps.asset_info.clone(),
            gas_validation_offset,
        )
        .await?;

    let intrinsic_gas = approx_intrinsic_cost(
        &intent_to_sign.encode_execute(),
        context.stored_authorization.is_some(),
    );

    let gas_estimate =
        GasEstimate::from_combined_gas(sim_result.gCombined.to(), intrinsic_gas, deps.quote_config);
    debug!(eoa = %intent.eoa, gas_estimate = ?gas_estimate, "Estimated intent");

    // Fill combinedGas
    intent_to_sign.combinedGas = U256::from(gas_estimate.intent);
    // Calculate the real fee
    let extra_payment = estimate_extra_fee(
        &chain,
        &intent_to_sign,
        context.stored_authorization.clone(),
        &native_fee_estimate,
        &gas_estimate,
        deps.contracts.orchestrator.address,
    )
    .await?
        * U256::from(10u128.pow(token.decimals as u32))
        / eth_price;

    // Fill empty dummy signature
    intent_to_sign.signature = bytes!("");
    intent_to_sign.funderSignature = bytes!("");

    // Fill payment information
    //
    // If the fee has already been specified (multichain inputs only), we only simulate to get
    // asset diffs. Otherwise, we simulate to get the fee.
    intent_to_sign.set_legacy_payment_amount(
        context.intent_kind.multi_input_fee().unwrap_or(
            extra_payment + U256::from((payment_per_gas * gas_estimate.tx as f64).ceil()),
        ),
    );

    let fee_token_deficit = intent_to_sign.totalPaymentMaxAmount.saturating_sub(fee_token_balance);
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
        ChainAssetDiffs::new(asset_diffs, &quote, deps.fee_tokens, deps.price_oracle).await?;

    Ok((chain_asset_diffs, quote))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approx_intrinsic_cost_without_auth() {
        // Test with empty calldata and no auth
        assert_eq!(approx_intrinsic_cost(&[], false), 21000);

        // Test with some calldata and no auth
        let calldata = vec![0u8; 100];
        assert_eq!(approx_intrinsic_cost(&calldata, false), 21000 + 100 * 16);
    }

    #[test]
    fn test_approx_intrinsic_cost_with_auth() {
        // Test with empty calldata and auth
        assert_eq!(approx_intrinsic_cost(&[], true), 21000 + PER_EMPTY_ACCOUNT_COST);

        // Test with some calldata and auth
        let calldata = vec![0u8; 100];
        assert_eq!(
            approx_intrinsic_cost(&calldata, true),
            21000 + PER_EMPTY_ACCOUNT_COST + 100 * 16
        );
    }

    #[test]
    fn test_approx_intrinsic_cost_large_calldata() {
        // Test with large calldata
        let calldata = vec![0xff; 1000];
        assert_eq!(approx_intrinsic_cost(&calldata, false), 21000 + 1000 * 16);
    }
}
