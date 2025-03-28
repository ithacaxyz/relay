//! Prepare calls related end-to-end test cases

use crate::e2e::{
    MockErc20, TxContext, build_pre_ops,
    environment::{Environment, mint_erc20s},
    eoa::EoaKind,
    send_prepared_calls,
};
use alloy::{
    primitives::{Address, TxHash, TxKind, U256},
    providers::{PendingTransactionBuilder, Provider},
    rpc::types::TransactionRequest,
    sol_types::SolCall,
};
use eyre::Context;
use futures_util::future::try_join_all;
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Call, CreatableAccount, KeyType, KeyWith712Signer,
        rpc::{
            CreateAccountParameters, GetAccountsParameters, GetKeysParameters, KeySignature, Meta,
            PrepareCallsCapabilities, PrepareCallsParameters, PrepareCallsResponse,
            PrepareCreateAccountCapabilities, PrepareCreateAccountParameters,
            PrepareCreateAccountResponse,
        },
    },
};

pub async fn prep_account<'a>(
    env: &mut Environment,
    calls: &[Call],
    authorize_keys: &[&KeyWith712Signer],
    pre_ops: &[TxContext<'a>],
    tx_num: usize,
) -> eyre::Result<TxHash> {
    let prep_signer = authorize_keys[0];

    // This will fetch a valid PREPAccount that the user will need to sign over the address
    let PrepareCreateAccountResponse {
        capabilities: _,
        digests: _,
        context,
        address: prep_address,
    } = env
        .relay_endpoint
        .prepare_create_account(PrepareCreateAccountParameters {
            capabilities: PrepareCreateAccountCapabilities {
                authorize_keys: try_join_all(
                    authorize_keys.iter().map(async |k| k.to_authorized(None).await),
                )
                .await?,
                delegation: env.delegation,
            },
            chain_id: env.chain_id,
        })
        .await?;

    assert!(prep_address == context.account.address);

    // Mint ERC20 tokens into the account
    mint_erc20s(&[env.erc20, env.erc20_alt], &[prep_address], &env.provider).await?;
    env.provider
        .send_transaction(TransactionRequest {
            to: Some(TxKind::Call(prep_address)),
            value: Some(U256::from(100e18)),
            ..Default::default()
        })
        .await?
        .get_receipt()
        .await?;

    // Generate all ID -> Account from the authorized keys
    let signatures = try_join_all(authorize_keys.iter().map(async |key| {
        Ok::<_, eyre::Error>(KeySignature {
            public_key: key.publicKey.clone(),
            key_type: key.keyType,
            value: key.id_sign(prep_address).await?.as_bytes().into(),
            prehash: false,
        })
    }))
    .await?;

    // Send the PREPAccount with its key identifiers and signatures
    let key_ids = env
        .relay_endpoint
        .create_account(CreateAccountParameters { context: context.clone(), signatures })
        .await?;

    let admin_key_id = key_ids[0].id;
    let init_calls_len = context.account.init_calls.len();
    match &mut env.eoa {
        EoaKind::Upgraded(_dyn_signer) => unreachable!(),
        EoaKind::Prep(account) => {
            *account = Some(CreatableAccount::new(context.account, key_ids));
        }
    };

    // Ensure the ID -> Account has been stored in storage before the onchain commit
    {
        let get_accounts_response = env
            .relay_endpoint
            .get_accounts(GetAccountsParameters { id: admin_key_id, chain_id: env.chain_id })
            .await?;
        assert!(get_accounts_response.iter().any(|r| r.address == prep_address));

        // Number of keys should be equal to the number of init_calls, since we only authorize admin
        // keys
        assert_eq!(get_accounts_response[0].keys.len(), init_calls_len);

        // Ensure getKeys returns the same keys from an account of getAccounts
        let get_keys_response = env
            .relay_endpoint
            .get_keys(GetKeysParameters {
                address: get_accounts_response[0].address,
                chain_id: env.chain_id,
            })
            .await?;

        assert_eq!(get_keys_response, get_accounts_response[0].keys);
    }

    let pre_ops = build_pre_ops(env, pre_ops, tx_num).await?;
    let PrepareCallsResponse { context, digest, .. } = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            calls: calls.to_vec(),
            chain_id: env.chain_id,
            from: env.eoa.address(),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: Vec::new(),
                revoke_keys: Vec::new(),
                meta: Meta {
                    fee_token: env.erc20,
                    key_hash: prep_signer.key_hash(),
                    // this will be the first UserOP
                    nonce: Some(U256::from(0)),
                },
                pre_ops,
                pre_op: false,
            },
        })
        .await?;

    // Sign UserOp digest
    let signature = prep_signer.sign_payload_hash(digest).await?;

    // Submit signed call
    let tx_hash = send_prepared_calls(env, prep_signer, signature, context).await?;

    // Check that transaction has been successful.
    let receipt = PendingTransactionBuilder::new(env.provider.root().clone(), tx_hash)
        .get_receipt()
        .await
        .wrap_err("Failed to get receipt")?;

    assert!(receipt.status());

    Ok(tx_hash)
}

#[tokio::test(flavor = "multi_thread")]
async fn basic_prep() -> eyre::Result<()> {
    if std::env::var("TEST_CI_FORK").is_ok() {
        // Test WILL run on a local envirnonment but it will be skipped in the odyssey_fork CI run.
        eprintln!("Test skipped until the new contracts are deployed.");
        return Ok(());
    }

    let mut env = Environment::setup_with_prep().await?;
    let target = env.erc20;
    let eoa_authorized = KeyWith712Signer::random_admin(KeyType::Secp256k1)?.unwrap();

    prep_account(
        &mut env,
        &[Call {
            target,
            value: U256::ZERO,
            data: MockErc20::transferCall { recipient: Address::ZERO, amount: U256::from(10) }
                .abi_encode()
                .into(),
        }],
        // todo: add test where key is not admin and should have permissions
        &[&eoa_authorized],
        &[],
        0,
    )
    .await?;

    Ok(())
}
