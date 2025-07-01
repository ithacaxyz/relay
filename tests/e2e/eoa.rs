use crate::e2e::{MockErc20, await_calls_status, environment::Environment, send_prepared_calls};
use alloy::{
    primitives::{Address, B256, U256},
    providers::ext::AnvilApi,
    sol_types::{SolCall, SolValue},
};
use relay::{
    rpc::RelayApiClient,
    signers::{DynSigner, Eip712PayLoadSigner},
    transactions::RelayTransaction,
    types::{
        Call, KeyType, KeyWith712Signer, Signature,
        rpc::{
            Meta, PrepareCallsCapabilities, PrepareCallsParameters, PrepareCallsResponse,
            PrepareUpgradeAccountParameters, PrepareUpgradeAccountResponse,
            UpgradeAccountCapabilities, UpgradeAccountParameters, UpgradeAccountSignatures,
        },
    },
};
/// An account that can be used to send intents.
pub struct MockAccount {
    pub address: Address,
    pub key: KeyWith712Signer,
}

impl MockAccount {
    /// Creates a new random account onchain.
    pub async fn new(env: &Environment) -> eyre::Result<Self> {
        Self::with_key(env, B256::random()).await
    }

    /// Creates a new account onchain with the given key.
    pub async fn with_key(env: &Environment, key: B256) -> eyre::Result<Self> {
        let eoa = DynSigner::from_signing_key(&B256::random().to_string()).await?;
        let key = KeyWith712Signer::mock_admin_with_key(KeyType::Secp256k1, key).unwrap().unwrap();

        let PrepareUpgradeAccountResponse { context, digests, .. } = env
            .relay_endpoint
            .prepare_upgrade_account(PrepareUpgradeAccountParameters {
                capabilities: UpgradeAccountCapabilities {
                    authorize_keys: vec![key.to_authorized()],
                },
                chain_id: Some(env.chain_id()),
                address: eoa.address(),
                delegation: env.delegation,
            })
            .await
            .unwrap();

        // Using ETH for payments
        env.provider().anvil_set_balance(eoa.address(), U256::from(100e18)).await?;

        env.relay_endpoint
            .upgrade_account(UpgradeAccountParameters {
                context,
                signatures: UpgradeAccountSignatures {
                    auth: eoa.sign_hash(&digests.auth).await?,
                    exec: eoa.sign_hash(&digests.exec).await?,
                },
            })
            .await
            .unwrap();

        let PrepareCallsResponse { context, digest, .. } = env
            .relay_endpoint
            .prepare_calls(PrepareCallsParameters {
                required_funds: vec![],
                calls: vec![Call {
                    to: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::mintCall { a: eoa.address(), val: U256::from(100e18) }
                        .abi_encode()
                        .into(),
                }],
                chain_id: env.chain_id(),
                from: Some(eoa.address()),
                capabilities: PrepareCallsCapabilities {
                    authorize_keys: vec![],
                    meta: Meta { fee_payer: None, fee_token: Address::ZERO, nonce: None },
                    pre_calls: vec![],
                    pre_call: false,
                    revoke_keys: vec![],
                },
                state_overrides: Default::default(),
                key: Some(key.to_call_key()),
            })
            .await
            .unwrap();

        let signature = key.sign_payload_hash(digest).await?;

        let bundle_id = send_prepared_calls(env, &key, signature, context).await.unwrap();

        // Wait for bundle to not be pending.
        let status = await_calls_status(env, bundle_id).await?;

        assert!(status.status.is_final());

        Ok(MockAccount { address: eoa.address(), key })
    }

    /// Prepares a simple transaction from the account which is ready to be sent to the transacton
    /// service.
    pub async fn prepare_tx(&self, env: &Environment) -> RelayTransaction {
        let PrepareCallsResponse { context, digest, .. } = env
            .relay_endpoint
            .prepare_calls(PrepareCallsParameters {
                required_funds: vec![],
                calls: vec![],
                chain_id: env.chain_id(),
                from: Some(self.address),
                capabilities: PrepareCallsCapabilities {
                    authorize_keys: vec![],
                    meta: Meta { fee_payer: None, fee_token: env.erc20, nonce: None },
                    pre_calls: vec![],
                    pre_call: false,
                    revoke_keys: vec![],
                },
                state_overrides: Default::default(),
                key: Some(self.key.to_call_key()),
            })
            .await
            .unwrap();

        // todo(onbjerg): this assumes a single intent
        let mut quote = context.take_quote().unwrap().ty().quotes[0].clone();
        quote.output.signature = Signature {
            innerSignature: self.key.sign_payload_hash(digest).await.unwrap(),
            keyHash: self.key.key_hash(),
            prehash: false,
        }
        .abi_encode_packed()
        .into();

        RelayTransaction::new(quote, None)
    }
}
