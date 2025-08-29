use crate::e2e::{
    AuthKind,
    cases::{upgrade_account_eagerly, upgrade_account_lazily},
    environment::Environment,
};
use alloy::{eips::eip7702::constants::EIP7702_DELEGATION_DESIGNATOR, primitives::{Address, Bytes, B256}, rpc::types::state::{AccountOverride, StateOverridesBuilder}};
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{Account, KeyType, KeyWith712Signer, rpc::VerifySignatureParameters},
};

#[tokio::test(flavor = "multi_thread")]
async fn verify_signature() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();
    let eoa = env.eoa.address();
    upgrade_account_lazily(&env, &[key.to_authorized()], AuthKind::Auth).await?;

    // Need the state override since the account is not on onchain, and we need to query for the eip712 domain name and version to get a signing digest.
    let account = Account::new(eoa, env.provider()).with_overrides(
        StateOverridesBuilder::with_capacity(1)
            .append(
                eoa,
                AccountOverride::default()
                    .with_code(Bytes::from(
                        [
                            &EIP7702_DELEGATION_DESIGNATOR,
                            env.config.delegation_proxy.as_slice(),
                        ]
                        .concat(),
                    ))
            )
            .build(),
    );
    let digest = B256::random();
    let signature = key.sign_payload_hash(account.digest_erc1271(digest).await?).await?;

    let verify = |address: Address| {
        env.relay_endpoint.verify_signature(VerifySignatureParameters {
            address,
            chain_id: env.chain_id(),
            digest,
            signature: signature.clone(),
        })
    };

    // assert that we can verify signature against account in storage (not onchain)
    assert!(verify(eoa).await?.valid);

    // assert that we can verify signature against account onchain
    upgrade_account_eagerly(&env, &[key.to_authorized()], &key, AuthKind::Auth).await?;
    assert!(verify(eoa).await?.valid);

    Ok(())
}
