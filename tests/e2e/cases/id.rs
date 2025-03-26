use crate::e2e::{cases::prep_account, config::AccountConfig, eoa::EoaKind};
use relay::{
    rpc::RelayApiClient,
    types::{
        AccountRegistry::AccountRegistryCalls,
        KeyType, KeyWith712Signer,
        rpc::{AccountResponse, AuthorizeKeyResponse, GetAccountsParameters},
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn register_id() -> eyre::Result<()> {
    let mut env = AccountConfig::Prep.setup_environment().await?;

    let admin_key = KeyWith712Signer::random_admin(KeyType::WebAuthnP256)?.unwrap();
    prep_account(&mut env, &[], &[&admin_key], &[], 0).await?;

    if let EoaKind::Prep(account) = env.eoa {
        let account = account.unwrap();

        let admin_key_hash = admin_key.key_hash();

        // Generate ID from signature
        let id = account.id_signatures[0]
            .signature
            .recover_address_from_prehash(&admin_key.id_digest(account.prep.address))
            .unwrap();

        let (key_hash, addresses) =
            AccountRegistryCalls::id_infos(vec![id], env.entrypoint, env.provider)
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
        )
    } else {
        unreachable!();
    }

    Ok(())
}
