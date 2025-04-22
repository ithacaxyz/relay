use crate::e2e::{
    ExpectedOutcome, TxContext, cases::prep_account, config::AccountConfig, eoa::EoaKind,
};
use relay::{
    rpc::RelayApiClient,
    types::{
        AccountRegistry::AccountRegistryCalls,
        KeyType, KeyWith712Signer,
        rpc::{GetAccountsParameters, GetKeysParameters},
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn register_and_unregister_id() -> eyre::Result<()> {
    let mut env = AccountConfig::Prep.setup_environment().await?;

    let admin_key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    let backup_key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();

    prep_account(&mut env, &[&admin_key, &backup_key]).await?;

    TxContext { expected: ExpectedOutcome::Pass, key: Some(&admin_key), ..Default::default() }
        .process(0, &env)
        .await?;

    let account_registry = env.relay_endpoint.health().await?.account_registry;

    if let EoaKind::Prep(ref account) = env.eoa {
        let account = account.clone().unwrap();

        let (key_hash, addresses) = AccountRegistryCalls::id_infos(
            vec![admin_key.id()],
            account_registry,
            env.provider.clone(),
        )
        .await?
        .pop()
        .unwrap()
        .unwrap();

        // Ensure ID -> (KeyHash, Address[]) matches
        assert_eq!(key_hash, admin_key.key_hash());
        assert_eq!(&addresses, &[account.prep.address]);

        // wallet_getAccounts should return the address and both associated authorized keys
        let response = env
            .relay_endpoint
            .get_accounts(GetAccountsParameters { id: admin_key.id(), chain_id: env.chain_id })
            .await?;

        assert_eq!(response.len(), 1);
        assert_eq!(response[0].address, account.prep.address);
        assert!(response[0].keys.contains(&admin_key.to_authorized(None).await?.into_response()));
        assert!(response[0].keys.contains(&backup_key.to_authorized(None).await?.into_response()));

        TxContext {
            revoke_keys: vec![&admin_key],
            expected: ExpectedOutcome::Pass,
            key: Some(&admin_key),
            ..Default::default()
        }
        .process(1, &env)
        .await?;

        // Ensure the onchain account registry no longer has the revoked key entry.
        // Ensure that the local storage mapping (used for when the account is not deployed) does
        // not return the account, since the EOA is actually delegated.
        let response = env
            .relay_endpoint
            .get_accounts(GetAccountsParameters { id: admin_key.id(), chain_id: env.chain_id })
            .await;

        assert!(response.is_err()); // KeysError::UnknownKeyId
        assert!(
            AccountRegistryCalls::id_infos(
                vec![admin_key.id()],
                account_registry,
                env.provider.clone()
            )
            .await?
            .pop()
            .unwrap()
            .is_none()
        );

        // Backup key -> Account still exists
        assert!(
            AccountRegistryCalls::id_infos(
                vec![backup_key.id()],
                account_registry,
                env.provider.clone()
            )
            .await?
            .pop()
            .unwrap()
            .is_some()
        );

        assert_eq!(
            env.relay_endpoint
                .get_accounts(GetAccountsParameters { id: backup_key.id(), chain_id: env.chain_id })
                .await?
                .len(),
            1
        );

        // Ensure getKeys returns ONLY the backup key.
        assert_eq!(
            env.relay_endpoint
                .get_keys(GetKeysParameters {
                    address: account.prep.address,
                    chain_id: env.chain_id
                })
                .await?,
            vec![backup_key.to_authorized(None).await?.into_response()]
        );

        // Bork EOA with no admin keys by revoking the remaining backup key
        TxContext {
            revoke_keys: vec![&backup_key],
            expected: ExpectedOutcome::Pass,
            key: Some(&backup_key),
            ..Default::default()
        }
        .process(2, &env)
        .await?;

        // None of the keys should return any account
        assert!(
            env.relay_endpoint
                .get_accounts(GetAccountsParameters { id: admin_key.id(), chain_id: env.chain_id })
                .await
                .is_err() // KeysError::UnknownKeyId
        );

        assert!(
            env.relay_endpoint
                .get_accounts(GetAccountsParameters { id: backup_key.id(), chain_id: env.chain_id })
                .await
                .is_err() // KeysError::UnknownKeyId
        );

        // Original account should not return any key
        assert!(
            env.relay_endpoint
                .get_keys(GetKeysParameters {
                    address: account.prep.address,
                    chain_id: env.chain_id
                })
                .await?
                .is_empty()
        );
    } else {
        unreachable!();
    }

    Ok(())
}
