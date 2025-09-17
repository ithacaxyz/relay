use std::collections::{BTreeSet, HashMap, HashSet};

use crate::e2e::{
    AuthKind,
    MockErc721::{self},
    await_calls_status,
    cases::upgrade_account_eagerly,
    common_calls,
    environment::{Environment, mint_erc20s},
    send_prepared_calls,
};
use alloy::{
    primitives::{Address, U64, U256},
    sol_types::SolCall,
};
use relay::{
    asset::AssetInfoService,
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Asset, AssetType, Call, IERC20, KeyType, KeyWith712Signer,
        rpc::{
            AddressOrNative, AssetFilterItem, GetAssetsParameters, Meta, PrepareCallsCapabilities,
            PrepareCallsParameters, PrepareCallsResponse,
        },
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn asset_info() -> eyre::Result<()> {
    // Setup environment
    let env = Environment::setup().await?;
    let assets = vec![Asset::Native, Asset::Token(env.erc20), Asset::Token(env.erc20s[1])];
    let provider = env.provider().clone();

    // Spawn AssetInfoService
    let service = AssetInfoService::new(10, &env.config);
    let handle = service.handle();
    tokio::spawn(service);

    let assets = handle.get_asset_info_list(&provider, assets).await?;

    assert_eq!(assets.len(), 3);
    for (_, asset) in assets {
        assert!(asset.metadata.decimals.is_some());
        assert!(asset.metadata.symbol.is_some());
    }

    Ok(())
}

/// Ensures that asset diffs do not include the fee payment diff on the payer.
#[tokio::test(flavor = "multi_thread")]
async fn asset_diff_no_fee() -> eyre::Result<()> {
    // setup environment
    let env = Environment::setup().await?;
    let admin_key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();

    upgrade_account_eagerly(
        &env,
        &[admin_key.to_authorized()],
        &admin_key,
        crate::e2e::AuthKind::Auth,
    )
    .await?;

    // create prepare_call request
    for fee_token in [env.fee_token, Address::ZERO] {
        let params = PrepareCallsParameters {
            from: Some(env.eoa.address()),
            calls: vec![], // fill in per test
            chain_id: env.chain_id(),
            capabilities: PrepareCallsCapabilities {
                meta: Meta { fee_payer: None, fee_token: Some(fee_token), nonce: None },
                authorize_keys: vec![],
                revoke_keys: vec![],
                pre_calls: vec![],
                pre_call: false,
                required_funds: vec![],
            },
            state_overrides: Default::default(),
            balance_overrides: Default::default(),

            key: Some(admin_key.to_call_key()),
        };
        let response = env.relay_endpoint.prepare_calls(params).await?.capabilities.asset_diff;

        // There should be no diff found for the eoa.
        let asset_diffs = response.asset_diffs.get(&env.chain_id()).unwrap();
        assert!(!asset_diffs.0.iter().any(|(addr, _)| *addr == env.eoa.address()));
    }

    Ok(())
}

/// Ensures that asset diffs coming from prepare_calls are as expected for both ERC721 and ERC20.
#[tokio::test(flavor = "multi_thread")]
async fn asset_diff() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    // Prepare account
    let admin_key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    upgrade_account_eagerly(&env, &[admin_key.to_authorized()], &admin_key, AuthKind::Auth).await?;

    mint_erc20s(&[env.erc20s[5]], &[env.eoa.address()], env.provider()).await?;

    // create prepare_call request
    let params = PrepareCallsParameters {
        from: Some(env.eoa.address()),
        calls: vec![], // fill in per test
        chain_id: env.chain_id(),
        capabilities: PrepareCallsCapabilities {
            meta: Meta { fee_payer: None, fee_token: Some(Address::ZERO), nonce: None },
            authorize_keys: vec![],
            revoke_keys: vec![],
            pre_calls: vec![],
            pre_call: false,
            required_funds: vec![],
        },
        state_overrides: Default::default(),
        balance_overrides: Default::default(),

        key: Some(admin_key.to_call_key()),
    };

    let prepare_calls = |calls: Vec<Call>| {
        let mut p = params.clone();
        p.calls = calls;
        async { env.relay_endpoint.prepare_calls(p).await }
    };

    let find_diff =
        |resp: &PrepareCallsResponse, eoa: Address, token: Address, is_incoming: bool| {
            let asset_diffs =
                resp.capabilities.asset_diff.asset_diffs.get(&env.chain_id()).unwrap();
            asset_diffs
                .0
                .iter()
                .filter(|(addr, _)| addr == &eoa)
                .flat_map(|(_, diffs)| diffs.iter())
                .find(|d| d.address == Some(token) && d.direction.is_incoming() == is_incoming)
                .map(|d| d.value)
        };

    let mint_erc721 = if std::env::var("TEST_ERC721").is_ok() {
        Call { to: env.erc721, value: U256::ZERO, data: MockErc721::mintCall::SELECTOR.into() }
    } else {
        common_calls::mint(env.erc721, env.eoa.address(), U256::ZERO)
    };

    let is_incoming = true;

    // test1: eoa should receive exactly one new ERC721, and spend the ERC20
    let resp1 = prepare_calls(vec![
        common_calls::mint(env.erc20, env.eoa.address(), U256::from(10_000_000u64)),
        Call::transfer(env.erc20s[5], Address::ZERO, U256::from(1u64)),
        mint_erc721.clone(),
    ])
    .await?;
    let erc721_id = find_diff(&resp1, env.eoa.address(), env.erc721, is_incoming)
        .expect("must have received ERC721");
    assert!(find_diff(&resp1, env.eoa.address(), env.erc20s[5], !is_incoming).is_some());

    // test2: eoa mints and transfers the NFT out. So, only the receiving address should have have
    // an inflow.
    let random_eoa = Address::random();

    let resp2 = prepare_calls(vec![
        common_calls::mint(env.erc20, env.eoa.address(), U256::from(10_000_000u64)),
        Call::transfer(env.erc20s[5], Address::ZERO, U256::from(1u64)),
        mint_erc721,
        common_calls::transfer_721(env.erc721, env.eoa.address(), random_eoa, erc721_id),
    ])
    .await?;

    // eoa should not hold the nfttoken
    assert!(find_diff(&resp2, env.eoa.address(), env.erc721, false).is_none());

    // random eoa should hold the nft token
    assert_eq!(find_diff(&resp2, random_eoa, env.erc721, is_incoming), Some(erc721_id));

    // ERC20 spend repeats
    assert!(find_diff(&resp2, env.eoa.address(), env.erc20s[5], !is_incoming).is_some());

    Ok(())
}

/// Ensures that asset diffs coming from prepare_calls contain token URIs for ERC721 tokens.
#[tokio::test(flavor = "multi_thread")]
async fn asset_diff_has_uri() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    // Prepare account
    let admin_key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    upgrade_account_eagerly(&env, &[admin_key.to_authorized()], &admin_key, AuthKind::Auth).await?;

    mint_erc20s(&[env.erc20s[5]], &[env.eoa.address()], env.provider()).await?;

    // ensure we always have the expected amount of unique tokens with URIs in our asset diffs.
    let ensure_tokens_with_uris = |resp: &PrepareCallsResponse, expected: usize| -> Vec<U256> {
        let asset_diffs = resp.capabilities.asset_diff.asset_diffs.get(&env.chain_id()).unwrap();
        let tokens = asset_diffs
            .0
            .iter()
            .flat_map(|(_, diffs)| diffs.iter())
            .filter(move |asset| {
                asset.address == Some(env.erc721)
                    && asset.token_kind == Some(AssetType::ERC721)
                    && asset.direction.is_incoming()
            })
            .filter(|d| d.metadata.uri.is_some())
            .map(|d| d.value)
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
        chain_id: env.chain_id(),
        capabilities: PrepareCallsCapabilities {
            meta: Meta { fee_token: Some(Address::ZERO), nonce: None, fee_payer: None },
            authorize_keys: vec![],
            revoke_keys: vec![],
            pre_calls: vec![],
            pre_call: false,
            required_funds: vec![],
        },
        state_overrides: Default::default(),
        balance_overrides: Default::default(),
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

#[tokio::test(flavor = "multi_thread")]
async fn get_assets_with_filter() -> eyre::Result<()> {
    let env = Environment::setup().await?;
    mint_erc20s(&[env.erc20s[5]], &[env.eoa.address()], &env.provider()).await?;

    let response = env
        .relay_endpoint
        .get_assets(GetAssetsParameters {
            account: env.eoa.address(),
            asset_filter: HashMap::from_iter([(
                env.chain_id(),
                vec![
                    AssetFilterItem {
                        address: AddressOrNative::Native,
                        asset_type: AssetType::Native,
                    },
                    AssetFilterItem {
                        address: AddressOrNative::Address(env.erc20s[5]),
                        asset_type: AssetType::ERC20,
                    },
                    AssetFilterItem {
                        address: AddressOrNative::Address(env.fee_token),
                        asset_type: AssetType::ERC20,
                    },
                ],
            )]),

            asset_type_filter: Default::default(),
            chain_filter: Default::default(),
        })
        .await?;

    let chain_user_assets = response.0.get(&env.chain_id()).unwrap();
    assert!(chain_user_assets.len() == 3);

    assert!(chain_user_assets[0].address == AddressOrNative::Native);
    assert!(chain_user_assets[1].address == AddressOrNative::Address(env.erc20s[5]));
    assert!(chain_user_assets[2].address == AddressOrNative::Address(env.fee_token));

    assert!(chain_user_assets[0].asset_type == AssetType::Native);
    assert!(chain_user_assets[1].asset_type == AssetType::ERC20);
    assert!(chain_user_assets[2].asset_type == AssetType::ERC20);

    assert!(chain_user_assets[0].balance > U256::ZERO);
    assert!(chain_user_assets[1].balance > U256::ZERO);
    assert!(chain_user_assets[2].balance > U256::ZERO);

    // we do actually include price metadata for the native asset
    assert!(chain_user_assets[0].metadata.is_some());
    assert!(chain_user_assets[1].metadata.is_some());
    assert!(chain_user_assets[2].metadata.is_some());

    Ok(())
}

/// Ensures that querying assets without a filter returns all relay chains and fee tokens.
#[tokio::test(flavor = "multi_thread")]
async fn get_assets_no_filter() -> eyre::Result<()> {
    let env = Environment::setup().await?;
    mint_erc20s(&[env.erc20s[5]], &[env.eoa.address()], &env.provider()).await?;

    let response = env
        .relay_endpoint
        .get_assets(GetAssetsParameters {
            account: env.eoa.address(),
            asset_filter: Default::default(),
            asset_type_filter: Default::default(),
            chain_filter: Default::default(),
        })
        .await?;

    // Gets the number of fee tokens in the environment chain
    let chain_fee_tokens_num = env
        .relay_endpoint
        .get_capabilities(Some(vec![U64::from(env.chain_id())]))
        .await?
        .0
        .get(&env.chain_id())
        .unwrap()
        .fees
        .tokens
        .len();

    let chain_user_assets = response.0.get(&env.chain_id()).unwrap();
    assert!(chain_user_assets.len() == chain_fee_tokens_num);

    Ok(())
}

/// Ensures that querying assets without a filter returns fee tokens which also have prices
#[tokio::test(flavor = "multi_thread")]
async fn get_assets_price_no_filter() -> eyre::Result<()> {
    let env = Environment::setup().await?;
    mint_erc20s(&[env.erc20s[5]], &[env.eoa.address()], &env.provider()).await?;

    let response = env
        .relay_endpoint
        .get_assets(GetAssetsParameters {
            account: env.eoa.address(),
            asset_filter: Default::default(),
            asset_type_filter: Default::default(),
            chain_filter: Default::default(),
        })
        .await?;

    // Gets the number of fee tokens in the environment chain
    let chain_fee_tokens = env
        .relay_endpoint
        .get_capabilities(Some(vec![U64::from(env.chain_id())]))
        .await?
        .0
        .get(&env.chain_id())
        .unwrap()
        .fees
        .tokens
        .clone();

    let chain_fee_tokens_num = chain_fee_tokens.len();

    let chain_user_assets = response.0.get(&env.chain_id()).unwrap();
    assert!(chain_user_assets.len() == chain_fee_tokens_num);

    // check that the chain user assets are the same as the fee tokens
    let fee_token_addresses =
        chain_fee_tokens.iter().map(|token| token.asset.address).collect::<BTreeSet<_>>();
    let user_asset_addresses =
        chain_user_assets.iter().map(|asset| asset.address.address()).collect::<BTreeSet<_>>();
    assert_eq!(fee_token_addresses, user_asset_addresses);

    // check that all the assets have prices
    for asset in chain_user_assets {
        // check that it has metadata and has prices
        if !asset.address.is_native() {
            assert!(asset.metadata.as_ref().is_some_and(|meta| meta.fiat.is_some()));
        }
    }

    // check that there is only one native asset and one erc20 with the zero address
    assert!(chain_user_assets.iter().filter(|asset| asset.address.is_native()).count() == 1);

    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn asset_deficits() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    // Prepare account
    let admin_key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    upgrade_account_eagerly(&env, &[admin_key.to_authorized()], &admin_key, AuthKind::Auth).await?;

    mint_erc20s(&[env.erc20s[5]], &[env.eoa.address()], &env.provider()).await?;
    let balance =
        IERC20::new(env.erc20s[5], env.provider()).balanceOf(env.eoa.address()).call().await?;
    let amount = balance * U256::from(2);

    // create prepare_call request with a transfer exceeding balance
    let params = PrepareCallsParameters {
        from: Some(env.eoa.address()),
        calls: vec![
            Call::transfer(env.erc20s[5], Address::with_last_byte(1), amount),
            Call::transfer(env.erc20s[6], Address::with_last_byte(2), U256::from(1)),
        ],
        chain_id: env.chain_id(),
        capabilities: PrepareCallsCapabilities {
            meta: Meta { fee_payer: None, fee_token: Some(env.erc20s[5]), nonce: None },
            authorize_keys: vec![],
            revoke_keys: vec![],
            pre_calls: vec![],
            pre_call: false,
            required_funds: vec![],
        },
        state_overrides: Default::default(),
        balance_overrides: Default::default(),
        key: Some(admin_key.to_call_key()),
    };

    let output = env.relay_endpoint.prepare_calls(params).await?;
    let quote = &output.context.quote().unwrap().ty().quotes[0];
    let deficit_5 = &quote
        .asset_deficits
        .0
        .iter()
        .find(|deficit| deficit.address == Some(env.erc20s[5]))
        .unwrap();

    let deficit_6 = &quote
        .asset_deficits
        .0
        .iter()
        .find(|deficit| deficit.address == Some(env.erc20s[6]))
        .unwrap();

    assert_eq!(deficit_5.deficit, amount + quote.intent.total_payment_max_amount() - balance);
    assert_eq!(deficit_5.required, amount + quote.intent.total_payment_max_amount());
    assert_eq!(deficit_6.deficit, U256::from(1));
    assert_eq!(deficit_6.required, U256::from(1));

    // create prepare_call request with a transfer of entire balance
    let params = PrepareCallsParameters {
        from: Some(env.eoa.address()),
        calls: vec![Call::transfer(env.erc20s[5], Address::with_last_byte(1), balance)],
        chain_id: env.chain_id(),
        capabilities: PrepareCallsCapabilities {
            meta: Meta { fee_payer: None, fee_token: Some(env.erc20s[5]), nonce: None },
            authorize_keys: vec![],
            revoke_keys: vec![],
            pre_calls: vec![],
            pre_call: false,
            required_funds: vec![],
        },
        state_overrides: Default::default(),
        balance_overrides: Default::default(),
        key: Some(admin_key.to_call_key()),
    };

    let output = env.relay_endpoint.prepare_calls(params).await?;
    let quote = &output.context.quote().unwrap().ty().quotes[0];
    let deficit = &quote.asset_deficits.0[0];

    assert_eq!(deficit.address, Some(env.erc20s[5]));
    assert_eq!(deficit.deficit, quote.intent.total_payment_max_amount());
    assert_eq!(deficit.required, balance + quote.intent.total_payment_max_amount());
    assert_eq!(quote.fee_token_deficit, quote.intent.total_payment_max_amount());

    Ok(())
}
