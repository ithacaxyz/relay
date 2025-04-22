use crate::e2e::{TxContext, cases::prep::prep_account, config::AccountConfig};
use alloy_primitives::{Address, B256};
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{KeyType, KeyWith712Signer, rpc::VerifySignatureParameters},
};

#[tokio::test(flavor = "multi_thread")]
async fn verify_signature() -> eyre::Result<()> {
    let mut env = AccountConfig::Prep.setup_environment().await?;

    let key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();
    let account = prep_account(&mut env, &[&key]).await?;

    let digest = B256::random();
    let signature = key.sign_payload_hash(digest).await?;

    let verify_with_id = |id: Address| {
        env.relay_endpoint.verify_signature(VerifySignatureParameters {
            key_id_or_address: id,
            chain_id: env.chain_id,
            digest,
            signature: signature.clone(),
        })
    };

    // assert that we can verify signature against a key id
    assert!(verify_with_id(key.id()).await?.valid);

    // assert that we can verify signature against account address
    assert!(verify_with_id(account).await?.valid);

    // assert that verification fails for arbitrary id
    assert!(verify_with_id(Address::random()).await.is_err());

    // send dummy transaction to make sure account is getting deployed
    TxContext { key: Some(&key), ..Default::default() }.process(0, &env).await?;

    // assert that we can verify signature against a key id
    assert!(verify_with_id(key.id()).await?.valid);

    // assert that we can verify signature against account address
    assert!(verify_with_id(account).await?.valid);

    // assert that verification fails for arbitrary id
    assert!(verify_with_id(Address::random()).await.is_err());

    Ok(())
}
