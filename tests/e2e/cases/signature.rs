use crate::e2e::{TxContext, cases::prep::prep_account, config::AccountConfig};
use alloy::dyn_abi::SolType;
use alloy_primitives::{Address, B256};
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Account, KeyType, KeyWith712Signer, PREPAccount, PREPInitData, Signature,
        rpc::VerifySignatureParameters,
    },
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

    let proof = verify_with_id(key.id()).await?.proof.unwrap();

    // firstly verify the key id has indeed signed this account's address
    let Some(id_signature) = proof.id_signature else {
        panic!("should have id signature");
    };
    assert_eq!(
        id_signature.recover_address_from_prehash(&key.id_digest(account)).unwrap(),
        key.id()
    );

    // now verify that this is indeed a PREP with the returned initdata
    let Some(init_data) = proof.prep_init_data else {
        panic!("should have init data");
    };
    let init_calls = PREPInitData::abi_decode_params(&init_data).unwrap().calls;
    assert_eq!(PREPAccount::initialize(env.delegation, init_calls).address, account);

    // simulate an on-chain signature recovery
    let signature =
        Signature { innerSignature: signature.clone(), keyHash: proof.key_hash, prehash: false };

    let key_hash = Account::new(account, &env.provider)
        .with_delegation_override(&env.delegation)
        .initialize_and_validate_signature(init_data.clone(), digest, signature.clone())
        .await?;

    assert_eq!(key_hash, Some(proof.key_hash));

    // send dummy transaction to make sure account is getting deployed
    TxContext { key: Some(&key), ..Default::default() }.process(0, &env).await?;

    // assert that we can verify signature against a key id
    assert!(verify_with_id(key.id()).await?.valid);

    // assert that we can verify signature against account address
    assert!(verify_with_id(account).await?.valid);

    // assert that verification fails for arbitrary id
    assert!(verify_with_id(Address::random()).await.is_err());

    let proof = verify_with_id(account).await?.proof.unwrap();

    // for on-chain signatures we just need to directly call the account
    let key_hash =
        Account::new(account, &env.provider).validate_signature(digest, signature.clone()).await?;

    assert_eq!(key_hash, Some(proof.key_hash));

    Ok(())
}
