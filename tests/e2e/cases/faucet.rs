use crate::e2e::environment::Environment;
use alloy::primitives::{Address, U64, U256};
use jsonrpsee::core::client::ClientT;
use relay::types::{
    IERC20,
    rpc::{AddFaucetFundsParameters, AddFaucetFundsResponse},
};

/// Basic faucet funding test
#[tokio::test(flavor = "multi_thread")]
async fn add_faucet_funds_success() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let recipient = Address::random();
    let amount = U256::from(1_000_000_000_000_000_000u64); // 1 token

    let params = AddFaucetFundsParameters {
        token_address: env.fee_token,
        address: recipient,
        chain_id: env.chain_id(),
        value: amount,
    };

    let response: AddFaucetFundsResponse =
        env.relay_endpoint.request("wallet_addFaucetFunds", vec![params]).await?;

    assert!(
        response.transaction_hash.is_some(),
        "Transaction should succeed: {:?}",
        response.message
    );

    assert_eq!(
        response.message,
        Some("Faucet funding successful".to_string()),
        "Should return success message"
    );

    // Fetch fee tokens for this chain and verify exactly one token was minted to `amount`.
    let caps: relay::types::rpc::RelayCapabilities = env
        .relay_endpoint
        .request("wallet_getCapabilities", vec![Some(vec![U64::from(env.chain_id())])])
        .await?;

    let fee_tokens = &caps.chain(env.chain_id()).fees.tokens;
    let mut non_zero = 0;
    for t in fee_tokens.iter() {
        let token_addr = t.asset.address;
        if token_addr.is_zero() {
            // native is not minted by the faucet
            continue;
        }
        let bal = IERC20::IERC20Instance::new(token_addr, env.provider())
            .balanceOf(recipient)
            .call()
            .await?;
        if bal > U256::ZERO {
            assert_eq!(bal, amount, "Minted amount should match request");
            non_zero += 1;
        }
    }
    assert_eq!(non_zero, 1, "Exactly one fee token should be minted");

    Ok(())
}

/// Unsupported chain test
#[tokio::test(flavor = "multi_thread")]
async fn add_faucet_funds_unsupported_chain() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let recipient = Address::random();
    let amount = U256::from(1_000_000_000_000_000_000u64);

    let params = AddFaucetFundsParameters {
        token_address: env.fee_token,
        address: recipient,
        chain_id: 99999,
        value: amount,
    };

    let result: eyre::Result<AddFaucetFundsResponse> =
        env.relay_endpoint.request("wallet_addFaucetFunds", vec![params]).await.map_err(Into::into);

    assert!(result.is_err(), "Should fail for unsupported chain");

    let err = result.unwrap_err().to_string();
    assert!(err.contains("unsupported chain 99999"), "Error should mention unsupported chain id");

    Ok(())
}

/// Faucet with zero amount
#[tokio::test(flavor = "multi_thread")]
async fn add_faucet_funds_zero_amount() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let recipient = Address::random();

    let params = AddFaucetFundsParameters {
        token_address: env.fee_token,
        address: recipient,
        chain_id: env.chain_id(),
        value: U256::ZERO,
    };

    let response: AddFaucetFundsResponse =
        env.relay_endpoint.request("wallet_addFaucetFunds", vec![params]).await?;

    if response.transaction_hash.is_some() {
        let balance = IERC20::IERC20Instance::new(env.fee_token, env.provider())
            .balanceOf(recipient)
            .call()
            .await?;

        assert_eq!(balance, U256::ZERO, "Balance should be zero");
    }

    Ok(())
}

/// Invalid `token_address` parameter should return error message
#[tokio::test(flavor = "multi_thread")]
async fn add_faucet_funds_invalid_token_address() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let recipient = Address::random();
    let amount = U256::from(1_000_000_000_000_000_000u64);

    let params = AddFaucetFundsParameters {
        token_address: Address::random(),
        address: recipient,
        chain_id: env.chain_id(),
        value: amount,
    };

    let response: AddFaucetFundsResponse =
        env.relay_endpoint.request("wallet_addFaucetFunds", vec![params]).await?;

    assert!(
        response.transaction_hash.is_none(),
        "Transaction should not succeed for invalid token"
    );

    assert_eq!(
        response.message,
        Some("Token address not supported".to_string()),
        "Should return unsupported token error message"
    );

    Ok(())
}

/// Concurrent faucet requests
#[tokio::test(flavor = "multi_thread")]
async fn add_faucet_funds_concurrent_requests() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let recipients: Vec<Address> = (0..3).map(|_| Address::random()).collect();
    let amount = U256::from(500_000_000_000_000_000u64); // 0.5 tokens each

    let futures = recipients
        .iter()
        .map(|recipient| {
            let params = AddFaucetFundsParameters {
                token_address: env.fee_token,
                address: *recipient,
                chain_id: env.chain_id(),
                value: amount,
            };

            let client = env.relay_endpoint.clone();
            async move {
                client
                    .request::<AddFaucetFundsResponse, _>("wallet_addFaucetFunds", vec![params])
                    .await
            }
        })
        .collect::<Vec<_>>();

    let results = futures_util::future::join_all(futures).await;

    // All should succeed since mutex serializes the requests
    for (index, result) in results.iter().enumerate() {
        assert!(result.is_ok(), "Request should not error");
        let response = result.as_ref().unwrap();
        assert!(response.transaction_hash.is_some(), "Transaction should succeed");

        let balance = IERC20::IERC20Instance::new(env.fee_token, env.provider())
            .balanceOf(recipients[index])
            .call()
            .await?;

        assert_eq!(balance, amount, "Each recipient should have received tokens");
    }

    Ok(())
}
