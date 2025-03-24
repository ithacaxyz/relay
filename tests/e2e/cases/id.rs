use crate::e2e::{cases::prep_account, config::AccountConfig, eoa::EoaKind};
use alloy::primitives::PrimitiveSignature;
use relay::{
    rpc::RelayApiClient,
    types::{
        AccountRegistry::AccountRegistryInstance,
        rpc::{AccountResponse, AuthorizeKeyResponse, GetAccountsParameters},
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn register_id() -> eyre::Result<()> {
    let mut env = AccountConfig::Prep.setup_environment().await?;
    let authorized_key = env.eoa.prep_signer().to_authorized();
    prep_account(&mut env, &[], &[authorized_key]).await?;

    if let EoaKind::Prep { admin_key, account } = env.eoa {
        let admin_key_hash = admin_key.key_hash();
        let signature =
            PrimitiveSignature::from_raw(&account.id_signatures[0].id_signature).unwrap();

        // Generate ID from signature
        let id = signature
            .recover_address_from_prehash(&admin_key.identifier_digest(account.prep.address))
            .unwrap();

        let accounts =
            AccountRegistryInstance::new(env.entrypoint, env.provider).idInfo(id).call().await?;
        assert!(!accounts.accounts.is_empty());

        // Ensure ID -> (KeyHash, Address[]) matches
        let (key_hash, addresses) = accounts.try_decode().unwrap();
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
