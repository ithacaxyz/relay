use std::collections::HashSet;

use crate::e2e::{
    ExpectedOutcome,
    MockErc721::{self},
    TxContext, await_calls_status,
    cases::prep_account,
    common_calls,
    config::AccountConfig,
    environment::mint_erc20s,
    send_prepared_calls,
};
use alloy::{
    primitives::{Address, U256},
    sol_types::SolCall,
};
use relay::{
    asset::AssetInfoService,
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Asset, Call, KeyType, KeyWith712Signer, TokenKind,
        rpc::{Meta, PrepareCallsCapabilities, PrepareCallsParameters, PrepareCallsResponse},
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn asset_info() -> eyre::Result<()> {
    // Setup environment
    let env = AccountConfig::Prep.setup_environment().await?;
    let assets = vec![Asset::Native, Asset::Token(env.erc20), Asset::Token(env.erc20s[1])];
    let provider = env.provider.clone();

    // Spawn AssetInfoService
    let service = AssetInfoService::new(10);
    let handle = service.handle();
    tokio::spawn(service);

    let assets = handle.get_asset_info_list(&provider, assets).await?;

    assert_eq!(assets.len(), 3);
    for (_, asset) in assets {
        assert!(asset.decimals.is_some());
        assert!(asset.symbol.is_some());
    }

    Ok(())
}

/// Ensures that asset diffs coming from prepare_calls are as expected for both ERC721 and ERC20.
#[tokio::test(flavor = "multi_thread")]
async fn asset_diff() -> eyre::Result<()> {
    // setup environment and prep account
    let mut env = AccountConfig::Prep.setup_environment().await?;
    let admin_key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    prep_account(&mut env, &[&admin_key]).await?;
    TxContext { expected: ExpectedOutcome::Pass, key: Some(&admin_key), ..Default::default() }
        .process(0, &env)
        .await?;

    mint_erc20s(&[env.erc20s[5]], &[env.eoa.address()], &env.provider).await?;

    // create prepare_call request
    let params = PrepareCallsParameters {
        from: Some(env.eoa.address()),
        calls: vec![], // fill in per test
        chain_id: env.chain_id,
        capabilities: PrepareCallsCapabilities {
            meta: Meta { fee_payer: None, fee_token: Address::ZERO, nonce: None },
            authorize_keys: vec![],
            revoke_keys: vec![],
            pre_ops: vec![],
            pre_op: false,
        },
        key: Some(admin_key.to_call_key()),
    };

    let prepare_calls = |calls: Vec<Call>| {
        let mut p = params.clone();
        p.calls = calls;
        async { env.relay_endpoint.prepare_calls(p).await }
    };

    let find_diff = |resp: &PrepareCallsResponse, eoa: Address, token: Address, is_inflow: bool| {
        resp.capabilities
            .asset_diff
            .0
            .iter()
            .filter(|(addr, _)| addr == &eoa)
            .flat_map(|(_, diffs)| diffs.iter())
            .find(|d| d.address == Some(token) && d.value.is_negative() != is_inflow)
            .map(|d| d.value)
    };

    let mint_erc721 = if std::env::var("TEST_ERC721").is_ok() {
        Call { to: env.erc721, value: U256::ZERO, data: MockErc721::mintCall::SELECTOR.into() }
    } else {
        common_calls::mint(env.erc721, env.eoa.address(), U256::from(1337u64))
    };

    let is_inflow = true;

    // test1: eoa should receive exactly one new ERC721, and spend the ERC20
    let resp1 = prepare_calls(vec![
        common_calls::mint(env.erc20, env.eoa.address(), U256::from(10_000_000u64)),
        common_calls::transfer(env.erc20s[5], Address::ZERO, U256::from(1u64)),
        mint_erc721.clone(),
    ])
    .await?;
    let erc721_id = find_diff(&resp1, env.eoa.address(), env.erc721, is_inflow)
        .expect("must have received ERC721");
    assert!(find_diff(&resp1, env.eoa.address(), env.erc20s[5], !is_inflow).is_some());

    // test2: eoa mints and transfers the NFT out. So, only the receiving address should have have
    // an inflow.
    let random_eoa = Address::random();

    let resp2 = prepare_calls(vec![
        common_calls::mint(env.erc20, env.eoa.address(), U256::from(10_000_000u64)),
        common_calls::transfer(env.erc20s[5], Address::ZERO, U256::from(1u64)),
        mint_erc721,
        common_calls::transfer_721(
            env.erc721,
            env.eoa.address(),
            random_eoa,
            U256::from_le_slice(&erc721_id.to_le_bytes::<64>()[..32]),
        ),
    ])
    .await?;

    // eoa should not hold the nfttoken
    assert!(find_diff(&resp2, env.eoa.address(), env.erc721, false).is_none());

    // random eoa should hold the nft token
    assert_eq!(find_diff(&resp2, random_eoa, env.erc721, is_inflow), Some(erc721_id));

    // ERC20 spend repeats
    assert!(find_diff(&resp2, env.eoa.address(), env.erc20s[5], !is_inflow).is_some());

    Ok(())
}

/// Ensures that asset diffs coming from prepare_calls contain token URIs for ERC721 tokens.
#[tokio::test(flavor = "multi_thread")]
async fn asset_diff_has_uri() -> eyre::Result<()> {
    // setup environment and prep account
    let mut env = AccountConfig::Prep.setup_environment().await?;
    let admin_key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    prep_account(&mut env, &[&admin_key]).await?;
    TxContext { expected: ExpectedOutcome::Pass, key: Some(&admin_key), ..Default::default() }
        .process(0, &env)
        .await?;

    mint_erc20s(&[env.erc20s[5]], &[env.eoa.address()], &env.provider).await?;

    // ensure we always have the expected amount of unique tokens with URIs in our asset diffs.
    let ensure_tokens_with_uris = |resp: &PrepareCallsResponse, expected: usize| -> Vec<U256> {
        let tokens = resp
            .capabilities
            .asset_diff
            .0
            .iter()
            .flat_map(|(_, diffs)| diffs.iter())
            .filter(move |asset| {
                asset.address == Some(env.erc721)
                    && asset.token_kind == Some(TokenKind::ERC721)
                    && asset.value.is_positive()
            })
            .filter(|d| d.uri.is_some())
            .map(|d| U256::from_le_slice(&d.value.to_le_bytes::<64>()[..32]))
            .collect::<HashSet<U256>>();

        assert!(tokens.len() == expected);
        tokens.into_iter().collect()
    };

    // create prepare_call request with 2 mints.
    let mut params = PrepareCallsParameters {
        from: Some(env.eoa.address()),
        calls: if std::env::var("TEST_ERC721").is_ok() {
            vec![
                Call {
                    to: env.erc721,
                    value: U256::ZERO,
                    data: MockErc721::mintCall::SELECTOR.into(),
                },
                Call {
                    to: env.erc721,
                    value: U256::ZERO,
                    data: MockErc721::mintCall::SELECTOR.into(),
                },
            ]
        } else {
            vec![
                common_calls::mint(env.erc721, env.eoa.address(), U256::from(1337u64)),
                common_calls::mint(env.erc721, env.eoa.address(), U256::from(1338u64)),
            ]
        },
        chain_id: env.chain_id,
        capabilities: PrepareCallsCapabilities {
            meta: Meta { fee_token: Address::ZERO, nonce: None, fee_payer: None },
            authorize_keys: vec![],
            revoke_keys: vec![],
            pre_ops: vec![],
            pre_op: false,
        },
        key: Some(admin_key.to_call_key()),
    };

    // mint 2 NFTs
    let resp = env.relay_endpoint.prepare_calls(params.clone()).await?;
    let token_ids = ensure_tokens_with_uris(&resp, 2);

    let bundle_id = send_prepared_calls(
        &env,
        &admin_key,
        admin_key.sign_payload_hash(resp.digest).await?,
        resp.context,
    )
    .await?;

    // Wait for bundle to not be pending.
    let status = await_calls_status(&env, bundle_id).await?;
    assert!(status.status.is_final());

    // transfer 1st NFT
    params.calls = vec![common_calls::transfer_721(
        env.erc721,
        env.eoa.address(),
        Address::random(),
        token_ids[0],
    )];
    let resp = env.relay_endpoint.prepare_calls(params.clone()).await?;
    assert_eq!(vec![token_ids[0]], ensure_tokens_with_uris(&resp, 1));

    let bundle_id = send_prepared_calls(
        &env,
        &admin_key,
        admin_key.sign_payload_hash(resp.digest).await?,
        resp.context,
    )
    .await?;

    // Wait for bundle to not be pending.
    let status = await_calls_status(&env, bundle_id).await?;
    assert!(status.status.is_final());

    // burn 2nd NFT
    params.calls = vec![common_calls::burn_721(env.erc721, token_ids[1])];
    assert_eq!(
        vec![token_ids[1]],
        ensure_tokens_with_uris(&env.relay_endpoint.prepare_calls(params).await?, 1)
    );

    Ok(())
}
