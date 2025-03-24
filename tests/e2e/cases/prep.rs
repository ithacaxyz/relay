//! Prepare calls related end-to-end test cases

use crate::e2e::{MockErc20, environment::Environment, eoa::EoaKind, send_prepared_calls};
use alloy::{
    primitives::{Address, TxHash, U256},
    providers::{PendingTransactionBuilder, Provider},
    sol_types::{SolCall, SolValue},
};
use eyre::Context;
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Call, Signature,
        rpc::{
            AuthorizeKey, CreateAccountParameters, Meta, PrepareCallsCapabilities,
            PrepareCallsParameters, PrepareCallsResponse, PrepareCreateAccountCapabilities,
            PrepareCreateAccountParameters, PrepareCreateAccountResponse,
        },
    },
};

pub async fn prep_account(
    env: &mut Environment,
    calls: &[Call],
    authorize_keys: &[AuthorizeKey],
) -> eyre::Result<TxHash> {
    // This will fetch a valid PREPAccount that the user will need to sign over the address
    let PrepareCreateAccountResponse {
        capabilities: _,
        digests: _,
        context: server_account,
        address,
    } = env
        .relay_endpoint
        .prepare_create_account(PrepareCreateAccountParameters {
            capabilities: PrepareCreateAccountCapabilities {
                authorize_keys: authorize_keys.to_vec(),
                delegation: env.delegation,
            },
        })
        .await?;

    assert!(address == server_account.address);

    let id_signatures = match &mut env.eoa {
        EoaKind::Upgraded(_dyn_signer) => unreachable!(),
        EoaKind::Prep { admin_key: _, account } => {
            account.prep = server_account.clone();
            account.id_signatures.clone()
        }
    };

    // Send the PREPAccount with its key identifiers and signatures
    env.relay_endpoint
        .create_account(CreateAccountParameters {
            context: server_account,
            signatures: id_signatures,
        })
        .await?;

    // todo: assert that a createAccount reference exists

    let PrepareCallsResponse { context, digest, capabilities: _ } = env
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
