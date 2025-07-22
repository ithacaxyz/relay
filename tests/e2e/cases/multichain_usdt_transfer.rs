//! Multi-chain USDT transfer test case
//!
//! This test demonstrates cross-chain functionality with escrow and settler:
//! - Sets up 3 local chains
//! - Chain 1: User has N USDT balance
//! - Chain 2: User has N USDT balance
//! - Chain 3: User has 0 USDT balance (but has ETH for gas)
//! - Executes prepare_calls and send_prepared_calls on chain 3
//! - The output intent on chain 3 includes settler configuration
//! - Funding intents on chains 1 & 2 use escrow mechanism
//! - Attempts to transfer N+N USDT to address 0xbeef

use crate::e2e::{cases::upgrade_account_eagerly, *};
use alloy::primitives::{Address, U256, address};
use eyre::Result;
use relay::{
    config::TransactionServiceConfig,
    rpc::RelayApiClient,
    types::{
        IERC20, KeyType, KeyWith712Signer,
        rpc::{
            GetAssetsParameters, Meta, PrepareCallsCapabilities, PrepareCallsContext,
            PrepareCallsParameters, PrepareCallsResponse,
        },
    },
};

/// Tests successful cross-chain transfer using escrow mechanism.
///
/// User has USDT on chains 1&2, wants to send to recipient on chain 3.
/// Funds are locked in escrow, settler provides liquidity on destination.
#[tokio::test(flavor = "multi_thread")]
async fn test_multichain_usdt_transfer() -> Result<()> {
    // Set up the multichain transfer scenario
    let setup = MultichainTransferSetup::run().await?;
    let chain3_id = setup.env.chain_id_for(2);

    // Send prepared calls on chain 3
    let bundle_id =
        send_prepared_calls(&setup.env, &setup.key, setup.signature, setup.context).await?;
    let status = await_calls_status(&setup.env, bundle_id).await?;
    assert!(status.status.is_confirmed());

    // Target has receive our full transfer
    let assets = setup
        .env
        .relay_endpoint
        .get_assets(GetAssetsParameters::eoa(setup.target_recipient))
        .await?;
    assert!(
        assets.0.get(&chain3_id).unwrap().iter().any(|a| a.balance == setup.total_transfer_amount)
    );

    Ok(())
}

/// Result of multichain transfer setup
pub struct MultichainTransferSetup {
    // todo: make these private
    pub env: Environment,
    pub key: KeyWith712Signer,
    pub target_recipient: Address,
    pub balances: Vec<U256>,
    pub context: PrepareCallsContext,
    pub signature: alloy::primitives::Bytes,
    pub total_transfer_amount: U256,
    pub fees: Vec<U256>,
}

impl MultichainTransferSetup {
    /// Run the multichain transfer setup with default configuration
    pub async fn run() -> Result<Self> {
        Self::setup_with_config(None, false).await
    }

    /// Run the multichain transfer setup with a custom refund threshold
    pub async fn run_with_refund_threshold(seconds: u64) -> Result<Self> {
        Self::setup_with_config(Some(seconds), false).await
    }

    /// Run the multichain transfer setup with LayerZero
    pub async fn run_with_layer_zero() -> Result<Self> {
        Self::setup_with_config(None, true).await
    }

    async fn setup_with_config(
        escrow_refund_threshold: Option<u64>,
        use_layerzero: bool,
    ) -> Result<Self> {
        let num_chains = 3;
        // Set up environment configuration
        let mut env_config = EnvironmentConfig {
            num_chains,
            use_layerzero,
            transaction_service_config: TransactionServiceConfig {
                num_signers: 1,
                ..Default::default()
            },
            ..Default::default()
        };

        // Override refund threshold if specified
        if let Some(threshold) = escrow_refund_threshold {
            env_config.interop_config.escrow_refund_threshold = threshold;
        }

        let env = Environment::setup_with_config(env_config).await?;
        let wallet = env.eoa.address();

        // Get chain ID for chain 3 (destination chain)
        let chain3_id = env.chain_id_for(2);

        // Target address for USDT transfers
        let target_recipient = address!("000000000000000000000000000000000000beef");

        // Target recipient has no balance on chain 3
        let assets =
            env.relay_endpoint.get_assets(GetAssetsParameters::eoa(target_recipient)).await?;
        assert!(assets.0.get(&chain3_id).unwrap().iter().all(|a| a.balance == U256::ZERO));

        // Create a key for signing
        let key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

        // Account upgrade deployed onchain.
        upgrade_account_eagerly(&env, &[key.to_authorized()], &key, AuthKind::Auth).await?;

        // Get initial balances on all chains
        let mut balances = Vec::with_capacity(num_chains);
        for i in 0..num_chains {
            let balance =
                IERC20::new(env.erc20, env.provider_for(i)).balanceOf(wallet).call().await?;
            balances.push(balance);
        }

        // Calculate the total balance
        //
        // NOTE(onbjerg): We don't transfer the full balance because there has to be some left for
        // fees. For input intents, the fee is currently always paid in the requested asset.
        let total_transfer_amount = balances.iter().take(2).sum::<U256>();

        // Prepare the calls on chain 3 with required funds
        let prepare_result = env
            .relay_endpoint
            .prepare_calls(PrepareCallsParameters {
                calls: vec![common_calls::transfer(
                    env.erc20,
                    target_recipient,
                    total_transfer_amount,
                )],
                chain_id: chain3_id,
                from: Some(wallet),
                capabilities: PrepareCallsCapabilities {
                    authorize_keys: vec![],
                    revoke_keys: vec![],
                    meta: Meta { fee_payer: None, fee_token: Address::ZERO, nonce: None },
                    pre_calls: vec![],
                    pre_call: false,
                },
                state_overrides: Default::default(),
                balance_overrides: Default::default(),
                key: Some(key.to_call_key()),
                required_funds: vec![(env.erc20, total_transfer_amount)],
            })
            .await?;

        let PrepareCallsResponse { context, digest, .. } = prepare_result;
        let quotes = context.quote().expect("should always return quotes");
        // todo(joshie): this is wrong. it works for now, since we ignore the output fees in the
        // refund test, but we're essentially collecting fees for different tokens. (eg. the refund
        // test fee token on the output is native, while the fees on the input chains are env.erc20)
        let fees =
            quotes.ty().quotes.iter().map(|quote| quote.intent.totalPaymentMaxAmount).collect();

        // Verify that the output intent has settler configured
        let quotes = context.quote().expect("should have quotes");
        let output_quote = quotes.ty().quotes.last().expect("should have output quote");
        assert_ne!(
            output_quote.intent.settler,
            Address::ZERO,
            "Output intent should have settler configured"
        );

        // Verify funding intents are present (chains 1 & 2 will use escrow mechanism)
        let funding_quotes = &quotes.ty().quotes[..quotes.ty().quotes.len() - 1];
        assert_eq!(funding_quotes.len(), 2, "Should have 2 funding intents for chains 1 & 2");

        // Sign the digest
        let signature = key.sign_payload_hash(digest).await?;

        Ok(Self {
            env,
            key,
            target_recipient,
            balances,
            context,
            signature,
            total_transfer_amount,
            fees,
        })
    }
}
