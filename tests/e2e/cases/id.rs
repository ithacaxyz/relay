use crate::e2e::{
    ExpectedOutcome, TxContext, cases::prep_account, config::AccountConfig, eoa::EoaKind,
    process_tx,
};
use relay::{
    rpc::RelayApiClient,
    types::{
        AccountRegistry::AccountRegistryCalls,
        KeyType, KeyWith712Signer,
        rpc::{AccountResponse, AuthorizeKeyResponse, GetAccountsParameters, GetKeysParameters},
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn register_and_unregister_id() -> eyre::Result<()> {
    let mut env = AccountConfig::Prep.setup_environment().await?;

    let admin_key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    prep_account(&mut env, &[], &[&admin_key], &[], 0).await?;

    if let EoaKind::Prep(ref account) = env.eoa {
        let account = account.clone().unwrap();

        let admin_key_hash = admin_key.key_hash();

        // Generate ID from signature
        let id = account.id_signatures[0]
            .signature
            .recover_address_from_prehash(&admin_key.id_digest(account.prep.address))
            .unwrap();

        let (key_hash, addresses) =
            AccountRegistryCalls::id_infos(vec![id], env.entrypoint, env.provider.clone())
                .await?
                .pop()
                .unwrap()
                .unwrap();

        // Ensure ID -> (KeyHash, Address[]) matches
        assert_eq!(key_hash, admin_key_hash);
        assert_eq!(&addresses, &[account.prep.address]);

        // wallet_getAccounts should return the address and authorized keys from this ID
        let response = env
            .relay_endpoint
            .get_accounts(GetAccountsParameters { id, chain_id: env.chain_id })
            .await?;

        assert_eq!(
            response,
            vec![AccountResponse {
                address: account.prep.address,
                keys: vec![AuthorizeKeyResponse {
                    hash: admin_key_hash,
                    authorize_key: admin_key.to_authorized(),
                }]
            }]
        );

        // Bork EOA with no admin keys by revoking the only one
        process_tx(
            1,
            TxContext {
                revoke_keys: vec![&admin_key],
                expected: ExpectedOutcome::Pass,
                key: Some(&admin_key),
                ..Default::default()
            },
            &env,
        )
        .await?;

        // Ensure the account registry no longer has KeyID -> Account
        let response = env
            .relay_endpoint
            .get_accounts(GetAccountsParameters { id, chain_id: env.chain_id })
            .await?;

        assert!(response.is_empty());
        assert!(
            AccountRegistryCalls::id_infos(vec![id], env.entrypoint, env.provider.clone())
                .await?
                .pop()
                .unwrap()
                .is_none()
        );

        // Ensure getKeys returns the same empty keys list.
        let response = env
            .relay_endpoint
            .get_keys(GetKeysParameters { address: account.prep.address, chain_id: env.chain_id })
            .await?;
        assert!(response.is_empty());
    } else {
        unreachable!();
    }

    Ok(())
}
