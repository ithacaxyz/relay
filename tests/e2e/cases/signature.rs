use crate::e2e::{
    AuthKind,
    cases::{upgrade_account_eagerly, upgrade_account_lazily},
    environment::Environment,
};
use alloy::primitives::{Address, B256};
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{KeyType, KeyWith712Signer, rpc::VerifySignatureParameters},
};

#[tokio::test(flavor = "multi_thread")]
async fn verify_signature() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();
    let account = env.eoa.address();

    let digest = B256::random();
    let signature = key.sign_payload_hash(digest).await?;

    let verify = |address: Address| {
        env.relay_endpoint.verify_signature(VerifySignatureParameters {
            address,
            chain_id: env.chain_id(),
            digest,
            signature: signature.clone(),
        })
    };

    // assert that we can verify signature against account in storage (not onchain)
    upgrade_account_lazily(&env, &[key.to_authorized()], AuthKind::Auth).await?;
    assert!(verify(account).await?.valid);

    // assert that we can verify signature against account onchain
    upgrade_account_eagerly(&env, &[key.to_authorized()], &key, AuthKind::Auth).await?;
    assert!(verify(account).await?.valid);

    Ok(())
}
