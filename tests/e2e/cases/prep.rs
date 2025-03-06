//! Prepare calls related end-to-end test cases

use crate::e2e::{MockErc20, cases::upgrade::upgrade_account, environment::Environment};
use alloy::{
    primitives::{Address, B256, U256},
    providers::{PendingTransactionBuilder, Provider},
    sol_types::{SolCall, SolValue},
};
use eyre::Context;
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Call, CreateAccountCapabilities, CreateAccountParameters, CreateAccountResponse, KeyType,
        KeyWith712Signer, PrepareCallsCapabilities, PrepareCallsParameters, PrepareCallsResponse,
        SendPreparedCallsParameters, SendPreparedCallsResponse, SendPreparedCallsSignature,
        Signature,
        capabilities::{AuthorizeKey, Meta},
    },
};
use std::str::FromStr;

#[tokio::test(flavor = "multi_thread")]
async fn prep_account() -> eyre::Result<()> {
    let env = Environment::setup_with_prep().await?;

    // This will create an account request
    let CreateAccountResponse { address, capabilities } = env
        .relay_endpoint
        .create_account(CreateAccountParameters {
            capabilities: CreateAccountCapabilities {
                authorize_keys: vec![AuthorizeKey {
                    key: env.eoa.prep_signer().key().clone(),
                    // todo: add test where key is not admin and should have permissions
                    permissions: vec![],
                }],
                delegation: env.delegation,
            },
        })
        .await?;

    // todo: assert that a createAccount reference exists.

    // Address is fully reproducible with the same admin key.
    assert!(address == env.eoa.address());

    let PrepareCallsResponse { context, digest, capabilities } = env
        .relay_endpoint
        .prepare_calls(PrepareCallsParameters {
            calls: vec![
                Call {
                    target: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::transferCall {
                        recipient: Address::ZERO,
                        amount: U256::from(10),
                    }
                    .abi_encode()
                    .into(),
                }
                .clone(),
            ],
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
    let SendPreparedCallsResponse { id } = env
        .relay_endpoint
        .send_prepared_calls(SendPreparedCallsParameters {
            context,
            signature: SendPreparedCallsSignature {
                public_key: env.eoa.prep_signer().key().publicKey.clone(),
                key_type: env.eoa.prep_signer().key().keyType,
                value: signature,
            },
        })
        .await?;

    // Check that transaction has been successful.
    let tx_hash = B256::from_str(&id)?;
    let receipt = PendingTransactionBuilder::new(env.provider.root().clone(), tx_hash)
        .get_receipt()
        .await
        .wrap_err("Failed to get receipt")?;

    assert!(receipt.status());

    Ok(())
}
