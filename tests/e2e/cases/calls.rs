//! Prepare calls related end-to-end test cases

use crate::e2e::{
    AuthKind, MockErc20, cases::upgrade::upgrade_account, environment::Environment,
    send_prepared_calls,
};
use alloy::{
    primitives::{Address, U256},
    providers::{PendingTransactionBuilder, Provider},
    sol_types::{SolCall, SolValue},
};
use eyre::Context;
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Call, KeyType, KeyWith712Signer, Signature,
        rpc::{
            AuthorizeKey, Meta, PrepareCallsCapabilities, PrepareCallsParameters,
            PrepareCallsResponse,
        },
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn calls_with_upgraded_account() -> eyre::Result<()> {
    let (signers, keys) = [KeyType::Secp256k1, KeyType::WebAuthnP256]
        .into_iter()
        .map(|key_type| {
            let signer = KeyWith712Signer::random_admin(key_type).unwrap().unwrap();
            let key = signer.key().clone();
            (signer, AuthorizeKey { key, permissions: vec![], id_signature: None })
        })
        .collect::<(Vec<_>, Vec<_>)>();

    // Upgrade environment EOA signer with the above admin keys.
    let env = Environment::setup_with_upgraded().await?;
    upgrade_account(&env, &keys, AuthKind::Auth, vec![]).await?;

    // Every key will sign a ERC20 transfer
    let erc20_transfer = Call {
        target: env.erc20,
        value: U256::ZERO,
        data: MockErc20::transferCall { recipient: Address::ZERO, amount: U256::from(10) }
            .abi_encode()
            .into(),
    };

    // upgrade account UserOp had nonce 0;
    let user_op_nonce = 1;
    for (tx_num, signer) in signers.iter().enumerate() {
        let PrepareCallsResponse { context, digest, capabilities: _ } = env
            .relay_endpoint
            .prepare_calls(PrepareCallsParameters {
                calls: vec![erc20_transfer.clone()],
                chain_id: env.chain_id,
                from: env.eoa.address(),
                capabilities: PrepareCallsCapabilities {
                    authorize_keys: Vec::new(), // todo: add test authorize "inline"
                    revoke_keys: Vec::new(),
                    meta: Meta {
                        fee_token: env.erc20,
                        key_hash: signer.key_hash(),
                        nonce: Some(U256::from(tx_num + user_op_nonce)),
                    },
                    pre_ops: Vec::new(),
                    pre_op: false,
                },
            })
            .await?;

        // Sign UserOp digest
        // todo: innerSignature once estimateFee (or equivalent) is aware of the key instead of just
        // key type.
        let signature = Signature {
            innerSignature: signer.sign_payload_hash(digest).await?,
            keyHash: signer.key_hash(),
            prehash: false,
        }
        .abi_encode_packed()
        .into();

        // Submit signed call
        let tx_hash = send_prepared_calls(&env, signer, signature, context).await?;

        // Check that transaction has been successful.
        let receipt = PendingTransactionBuilder::new(env.provider.root().clone(), tx_hash)
            .get_receipt()
            .await
            .wrap_err("Failed to get receipt")?;

        assert!(receipt.status());
    }

    Ok(())
}
