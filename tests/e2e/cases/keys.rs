use crate::e2e::{
    AuthKind, ExpectedOutcome, MockErc20, TxContext, common_calls as calls, config::AccountConfig,
    environment::Environment, process_tx,
};
use alloy::{primitives::U256, sol_types::SolCall};
use relay::{
    rpc::RelayApiClient,
    types::{
        CallPermission,
        Delegation::{SpendInfo, SpendPeriod},
        KeyType, KeyWith712Signer,
        rpc::{AuthorizeKey, AuthorizeKeyResponse, GetKeysParameters, Permission, SpendPermission},
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn get_keys() -> eyre::Result<()> {
    let upgraded_account = AccountConfig::Upgraded;
    let mut env = upgraded_account.setup_environment().await?;
    let keys = [
        KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap(),
        KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap(),
        KeyWith712Signer::random_session(KeyType::P256)?.unwrap(),
    ];

    // Set session key permissions
    let permissions = vec![
        Permission::Spend(SpendPermission {
            limit: U256::from(1000),
            period: SpendPeriod::Day,
            token: env.erc20,
        }),
        Permission::Call(CallPermission {
            to: env.erc20,
            selector: MockErc20::transferCall::SELECTOR.into(),
        }),
    ];

    // Set expectable key responses from wallet_getKeys
    let expected_responses = keys
        .iter()
        .map(|key| {
            let permissions = if !key.isSuperAdmin { permissions.clone() } else { vec![] };
            AuthorizeKeyResponse {
                hash: key.key_hash(),
                authorize_key: AuthorizeKey { key: key.key().clone(), permissions },
            }
        })
        .collect::<Vec<_>>();

    // Upgrade account and check the first key has been added.
    {
        let mut tx = TxContext {
            authorization_keys: vec![keys[0].to_authorized()],
            expected: ExpectedOutcome::Pass,
            auth: Some(AuthKind::Auth),
            ..Default::default()
        };
        upgraded_account.handle_first_tx(&mut env, 0, &mut tx).await?;

        assert_eq!(env.get_eoa_authorized_keys().await?, expected_responses[..1]);
    }

    // Add the rest of the keys one by one.
    for (i, key) in [keys[1].to_authorized(), keys[2].to_permissioned_authorized(permissions)]
        .into_iter()
        .enumerate()
    {
        let mut tx = TxContext {
            authorization_keys: vec![key],
            expected: ExpectedOutcome::Pass,
            key: Some(&keys[0]),
            ..Default::default()
        };

        process_tx(i + 1, tx, &env).await?;

        assert_eq!(env.get_eoa_authorized_keys().await?, expected_responses[..(i + 2)]);
    }

    Ok(())
}
