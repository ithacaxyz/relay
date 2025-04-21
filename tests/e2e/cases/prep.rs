//! Prepare calls related end-to-end test cases

use crate::e2e::{
    ExpectedOutcome, TxContext, common_calls,
    environment::{Environment, mint_erc20s},
    eoa::EoaKind,
};
use alloy::{
    primitives::{Address, TxKind, U256},
    providers::Provider,
    rpc::types::TransactionRequest,
};
use futures_util::future::try_join_all;
use relay::{
    rpc::RelayApiClient,
    types::{
        CreatableAccount, KeyType, KeyWith712Signer,
        rpc::{
            CreateAccountParameters, GetAccountsParameters, GetKeysParameters, KeySignature,
            PrepareCreateAccountCapabilities, PrepareCreateAccountParameters,
            PrepareCreateAccountResponse,
        },
    },
};

/// It will attempt to create a PREPAccount by calling [`RelayApiClient::prepare_create_account`]
/// and  [`RelayApiClient::create_account`].
#[allow(clippy::too_many_arguments)]
pub async fn prep_account(
    env: &mut Environment,
    authorize_keys: &[&KeyWith712Signer],
) -> eyre::Result<Address> {
    // This will fetch a valid PREPAccount that the user will need to sign over the address
    let PrepareCreateAccountResponse {
        capabilities: _,
        digests: _,
        context,
        address: prep_address,
    } = env
        .relay_endpoint
        .prepare_create_account(PrepareCreateAccountParameters {
            capabilities: PrepareCreateAccountCapabilities {
                authorize_keys: try_join_all(
                    authorize_keys.iter().map(async |k| k.to_authorized(None).await),
                )
                .await?,
                delegation: env.delegation,
            },
            chain_id: env.chain_id,
        })
        .await?;

    assert!(prep_address == context.account.address);

    // Mint ERC20 tokens into the account
    mint_erc20s(&[env.erc20, env.fee_token], &[prep_address], &env.provider).await?;
    env.provider
        .send_transaction(TransactionRequest {
            to: Some(TxKind::Call(prep_address)),
            value: Some(U256::from(100e18)),
            ..Default::default()
        })
        .await?
        .get_receipt()
        .await?;

    // Generate all ID -> Account from the authorized keys
    let signatures = try_join_all(authorize_keys.iter().map(async |key| {
        Ok::<_, eyre::Error>(KeySignature {
            public_key: key.publicKey.clone(),
            key_type: key.keyType,
            value: key.id_sign(prep_address).await?.as_bytes().into(),
            prehash: false,
        })
    }))
    .await?;

    // Send the PREPAccount with its key identifiers and signatures
    let key_ids = env
        .relay_endpoint
        .create_account(CreateAccountParameters { context: context.clone(), signatures })
        .await?;

    let admin_key_id = key_ids[0].id;
    let init_calls_len = context.account.init_calls.len();
    match &mut env.eoa {
        EoaKind::Upgraded(_dyn_signer) => unreachable!(),
        EoaKind::Prep(account) => {
            *account = Some(CreatableAccount::new(context.account, key_ids));
        }
    };

    // Ensure the ID -> Account has been stored in storage before the onchain commit
    {
        let get_accounts_response = env
            .relay_endpoint
            .get_accounts(GetAccountsParameters { id: admin_key_id, chain_id: env.chain_id })
            .await?;
        assert!(get_accounts_response.iter().any(|r| r.address == prep_address));

        // Number of keys should be equal to the number of init_calls, since we only authorize admin
        // keys
        assert_eq!(get_accounts_response[0].keys.len(), init_calls_len);

        // Ensure getKeys returns the same keys from an account of getAccounts
        let get_keys_response = env
            .relay_endpoint
            .get_keys(GetKeysParameters {
                address: get_accounts_response[0].address,
                chain_id: env.chain_id,
            })
            .await?;

        assert_eq!(get_keys_response, get_accounts_response[0].keys);
    }

    Ok(prep_address)
}

#[tokio::test(flavor = "multi_thread")]
async fn basic_prep() -> eyre::Result<()> {
    let mut env = Environment::setup_with_prep().await?;
    let admin_key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    prep_account(&mut env, &[&admin_key]).await?;

    TxContext {
        expected: ExpectedOutcome::Pass,
        calls: vec![common_calls::transfer(env.erc20, env.erc20, U256::from(10))],
        key: Some(&admin_key),
        ..Default::default()
    }
    .process(0, &env)
    .await?;

    Ok(())
}
