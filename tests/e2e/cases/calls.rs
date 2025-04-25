//! Prepare calls related end-to-end test cases

use crate::e2e::{
    AuthKind, MockErc20, await_calls_status, cases::upgrade::upgrade_account,
    environment::Environment, send_prepared_calls,
};
use alloy::{
    primitives::{Address, U256},
    sol_types::SolCall,
};
use futures_util::future::try_join_all;
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Call, KeyType, KeyWith712Signer,
        rpc::{Meta, PrepareCallsCapabilities, PrepareCallsParameters, PrepareCallsResponse},
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn calls_with_upgraded_account() -> eyre::Result<()> {
    // Upgrade environment EOA signer with the above admin keys.
    let env = Environment::setup_with_upgraded().await?;

    let (signers, keys) = try_join_all(
        [KeyType::Secp256k1, KeyType::WebAuthnP256].into_iter().map(async |key_type| {
            let signer = KeyWith712Signer::random_admin(key_type).unwrap().unwrap();
            let auth = signer.to_authorized(Some(env.eoa.address())).await?;
            Ok::<_, eyre::Report>((signer, auth))
        }),
    )
    .await?
    .into_iter()
    .collect::<(Vec<_>, Vec<_>)>();

    upgrade_account(&env, &keys, AuthKind::Auth, vec![]).await?;

    // Every key will sign a ERC20 transfer
    let erc20_transfer = Call {
        to: env.erc20,
        value: U256::ZERO,
        data: MockErc20::transferCall { recipient: Address::ZERO, amount: U256::from(10) }
            .abi_encode()
            .into(),
    };

    // upgrade account UserOp had nonce 0;
    let user_op_nonce = 1;
    for (tx_num, signer) in signers.iter().enumerate() {
        let PrepareCallsResponse { context, digest, .. } = env
            .relay_endpoint
            .prepare_calls(PrepareCallsParameters {
                calls: vec![erc20_transfer.clone()],
                chain_id: env.chain_id,
                from: Some(env.eoa.address()),
                capabilities: PrepareCallsCapabilities {
                    authorize_keys: Vec::new(), // todo: add test authorize "inline"
                    revoke_keys: Vec::new(),
                    meta: Meta {
                        fee_token: env.fee_token,
                        key_hash: signer.key_hash(),
                        nonce: Some(U256::from(tx_num + user_op_nonce)),
                    },
                    pre_ops: Vec::new(),
                    pre_op: false,
                },
            })
            .await?;

        // Sign UserOp digest
        let signature = signer.sign_payload_hash(digest).await?;

        // Submit signed call
        let bundle_id = send_prepared_calls(&env, signer, signature, context).await?;

        // Wait for bundle to not be pending.
        let status = await_calls_status(&env, bundle_id).await?;
        assert!(status.status.is_final());
    }

    Ok(())
}
