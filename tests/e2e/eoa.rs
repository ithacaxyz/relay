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
            UpgradeAccountCapabilities, UpgradeAccountContext, UpgradeAccountParameters,
            UpgradeAccountSignatures,
        },
    },
};

/// Builder for [`MockAccount`]
pub struct MockAccountBuilder {
    key: Option<B256>,
    mint_erc20: bool,
}

impl Default for MockAccountBuilder {
    fn default() -> Self {
        Self { key: None, mint_erc20: true }
    }
}

impl MockAccountBuilder {
    /// Creates a new [`MockAccountBuilder`]
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the key for the account
    pub fn with_key(mut self, key: B256) -> Self {
        self.key = Some(key);
        self
    }

    /// Do not mint ERC20 token
    pub fn no_erc20_mint(mut self) -> Self {
        self.mint_erc20 = false;
        self
    }

    /// Create signer for the mock account, preparing the account for upgrade by calling
    /// `prepare_upgrade_account` and giving it a balance.
    ///
    /// This does not upgrade the account.
    pub async fn build_prepared(
        self,
        env: &Environment,
    ) -> eyre::Result<(MockAccount, UpgradeAccountContext, UpgradeAccountSignatures)> {
        let eoa = DynSigner::from_signing_key(&B256::random().to_string()).await?;
        let key = KeyWith712Signer::mock_admin_with_key(
            KeyType::Secp256k1,
            self.key.unwrap_or_else(B256::random),
        )
        .unwrap()
        .unwrap();

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

        // create signatures
        let signatures = UpgradeAccountSignatures {
            auth: eoa.sign_hash(&digests.auth).await?,
            exec: eoa.sign_hash(&digests.exec).await?,
        };

        Ok((MockAccount { address: eoa.address(), key }, context, signatures))
    }

    /// Build the [`MockAccount`]
    pub async fn build(self, env: &Environment) -> eyre::Result<MockAccount> {
        let eoa = DynSigner::from_signing_key(&B256::random().to_string()).await?;
        let key = KeyWith712Signer::mock_admin_with_key(
            KeyType::Secp256k1,
            self.key.unwrap_or_else(B256::random),
        )
        .unwrap()
        .unwrap();

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

        let mut calls = vec![];
        if self.mint_erc20 {
            calls.push(Call {
                to: env.erc20,
                value: U256::ZERO,
                data: MockErc20::mintCall { a: eoa.address(), val: U256::from(100e18) }
                    .abi_encode()
                    .into(),
            })
        };

        let PrepareCallsResponse { context, digest, .. } = env
            .relay_endpoint
            .prepare_calls(PrepareCallsParameters {
                calls,
                chain_id: env.chain_id(),
                from: Some(eoa.address()),
                capabilities: PrepareCallsCapabilities {
                    authorize_keys: vec![],
                    meta: Meta { fee_payer: None, fee_token: Some(Address::ZERO), nonce: None },
                    pre_calls: vec![],
                    pre_call: false,
                    revoke_keys: vec![],
                    required_funds: vec![],
                },
                state_overrides: Default::default(),
                balance_overrides: Default::default(),
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
}

/// An account that can be used to send intents.
pub struct MockAccount {
    pub address: Address,
    pub key: KeyWith712Signer,
}

// TODO: remove `new` and `with_key` methods, use `MockAccountBuilder` everywhere
impl MockAccount {
    /// Creates a new random account onchain.
    pub async fn new(env: &Environment) -> eyre::Result<Self> {
        MockAccountBuilder::new().build(env).await
    }

    /// Creates a new account onchain with the given key.
    pub async fn with_key(env: &Environment, key: B256) -> eyre::Result<Self> {
        MockAccountBuilder::new().with_key(key).build(env).await
    }

    /// Prepares a simple transaction from the account which is ready to be sent to the transacton
    /// service.
    pub async fn prepare_tx(&self, env: &Environment) -> RelayTransaction {
        let PrepareCallsResponse { context, digest, .. } = env
            .relay_endpoint
            .prepare_calls(PrepareCallsParameters {
                calls: vec![],
                chain_id: env.chain_id(),
                from: Some(self.address),
                capabilities: PrepareCallsCapabilities {
                    authorize_keys: vec![],
                    meta: Meta { fee_payer: None, fee_token: Some(env.erc20), nonce: None },
                    pre_calls: vec![],
                    pre_call: false,
                    revoke_keys: vec![],
                    required_funds: vec![],
                },
                state_overrides: Default::default(),
                balance_overrides: Default::default(),
                key: Some(self.key.to_call_key()),
            })
            .await
            .unwrap();

        // todo(onbjerg): this assumes a single intent
        let mut quote = context.take_quote().unwrap().ty().quotes[0].clone();
        quote.intent = quote.intent.with_signature(
            Signature {
                innerSignature: self.key.sign_payload_hash(digest).await.unwrap(),
                keyHash: self.key.key_hash(),
                prehash: false,
            }
            .abi_encode_packed()
            .into(),
        );

        RelayTransaction::new(quote, None, digest)
    }
}
