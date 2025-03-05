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
        Call, KeyType, KeyWith712Signer, PrepareCallsCapabilities, PrepareCallsParameters,
        PrepareCallsResponse, SendPreparedCallsParameters, SendPreparedCallsResponse,
        SendPreparedCallsSignature, Signature,
        capabilities::{AuthorizeKey, Meta},
    },
};
use std::str::FromStr;

#[tokio::test(flavor = "multi_thread")]
async fn calls_with_upgraded_account() -> eyre::Result<()> {
    let (signers, keys) = [KeyType::Secp256k1, KeyType::P256, KeyType::WebAuthnP256]
        .into_iter()
        .map(|key_type| {
            let signer = KeyWith712Signer::random_admin(key_type).unwrap().unwrap();
            let key = signer.key().clone();
            (signer, AuthorizeKey { key, permissions: vec![] })
        })
        .collect::<(Vec<_>, Vec<_>)>();

    // Upgrade environment EOA signer with the above admin keys.
    let env = Environment::setup().await?;
    upgrade_account(&env, keys.clone()).await;

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
        let PrepareCallsResponse { context, digest, capabilities } = env
            .relay_endpoint
            .prepare_calls(PrepareCallsParameters {
                calls: vec![erc20_transfer.clone()],
                chain_id: env.chain_id,
                // It's an upgraded account, so it's the eoa_signer
                from: env.eoa_signer.address(),
                capabilities: PrepareCallsCapabilities {
                    authorize_keys: None, // todo: add test authorize "inline"
                    revoke_keys: None,
                    meta: Meta {
                        fee_token: Some(env.erc20),
                        key_hash: signer.key_hash(),
                        nonce: U256::from(tx_num + user_op_nonce),
                    },
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
        let SendPreparedCallsResponse { id } = env
            .relay_endpoint
            .send_prepared_calls(SendPreparedCallsParameters {
                context,
                signature: SendPreparedCallsSignature {
                    public_key: signer.key().publicKey.clone(),
                    key_type: signer.key().keyType,
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
    }

    Ok(())
}
