//! Prepare calls related end-to-end test cases

use crate::e2e::{
    MockErc20, cases::upgrade::upgrade_account, environment::Environment, eoa::EoaKind,
    send_prepared_calls,
};
use alloy::{
    primitives::{Address, B256, TxHash, U256},
    providers::{PendingTransactionBuilder, Provider},
    sol_types::{SolCall, SolValue},
};
use eyre::Context;
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Call, CreateAccountCapabilities, CreateAccountParameters, CreateAccountResponse, KeyType,
        KeyWith712Signer, PREPAccount, PrepareCallsCapabilities, PrepareCallsParameters,
        PrepareCallsResponse, SendPreparedCallsParameters, SendPreparedCallsResponse,
        SendPreparedCallsSignature, Signature,
        capabilities::{AuthorizeKey, Meta},
    },
};
use std::str::FromStr;

pub async fn prep_account(
    env: &mut Environment,
    calls: &[Call],
    authorize_keys: &[AuthorizeKey],
) -> eyre::Result<TxHash> {
    // This will create an account request
    let CreateAccountResponse { address, capabilities } = env
        .relay_endpoint
        .create_account(CreateAccountParameters {
            capabilities: CreateAccountCapabilities {
                authorize_keys: authorize_keys.to_vec(),
                delegation: env.delegation,
            },
        })
        .await?;

    let init_calls = authorize_keys
        .iter()
        .flat_map(|key| {
            let (authorize_call, permissions_calls) = key.clone().into_calls(Address::ZERO);
            std::iter::once(authorize_call).chain(permissions_calls)
        })
        .collect::<Vec<_>>();

    match &mut env.eoa {
        EoaKind::Upgraded(dyn_signer) => unreachable!(),
        EoaKind::Prep { admin_key, account } => {
            *account = PREPAccount::initialize(env.delegation, init_calls);
        }
    }

    // todo: assert that a createAccount reference exists

    let PrepareCallsResponse { context, digest, capabilities } = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            calls: calls.to_vec(),
            chain_id: env.chain_id,
            from: env.eoa.address(),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: None,
                revoke_keys: None,
                meta: Meta {
                    fee_token: Some(env.erc20),
                    key_hash: env.eoa.prep_signer().key_hash(),
                    // this will be the first UserOP
                    nonce: U256::from(0),
                },
            },
        })
        .await?;

    // Sign UserOp digest
    // todo: innerSignature once estimateFee (or equivalent) is aware of the key instead of just
    // key type.
    let signature = Signature {
        innerSignature: env.eoa.prep_signer().sign_payload_hash(digest).await?,
        keyHash: env.eoa.prep_signer().key_hash(),
        prehash: false,
    }
    .abi_encode_packed()
    .into();

    // Submit signed call
    let tx_hash = send_prepared_calls(env, env.eoa.prep_signer(), signature, context).await?;

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
    let eoa_authorized = env.eoa.prep_signer().to_authorized();

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
        &[eoa_authorized],
    )
    .await?;

    Ok(())
}
