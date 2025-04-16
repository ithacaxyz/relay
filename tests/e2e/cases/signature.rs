use crate::e2e::{cases::prep::prep_account, config::AccountConfig};
use alloy_primitives::B256;
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        KeyType, KeyWith712Signer,
        rpc::{VerifySignatureParameters, VerifySignatureResponse},
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn verify_signature() -> eyre::Result<()> {
    let mut env = AccountConfig::Prep.setup_environment().await?;

    let key = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();
    prep_account(&mut env, &[&key]).await?;

    let digest = B256::random();
    let signature = key.sign_payload_hash(digest).await?;

    let VerifySignatureResponse { valid, .. } = env
        .relay_endpoint
        .verify_signature(VerifySignatureParameters {
            key_id: key.id(),
            chain_id: env.chain_id,
            digest,
            signature,
        })
        .await?;

    // assert that we can verify signature for a stored account
    assert!(valid);

    Ok(())
}
