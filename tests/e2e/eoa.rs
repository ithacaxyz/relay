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
        Call, CreatableAccount, KeyType, KeyWith712Signer, Signature,
        rpc::{
            CreateAccountParameters, KeySignature, Meta, PrepareCallsCapabilities,
            PrepareCallsParameters, PrepareCallsResponse, PrepareCreateAccountCapabilities,
            PrepareCreateAccountParameters, PrepareCreateAccountResponse,
        },
    },
};

/// Kind of EOA: PREP or Upgraded.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum EoaKind {
    Upgraded(DynSigner),
    Prep(Option<CreatableAccount>),
}

impl EoaKind {
    /// Create a new [`EoaKind`] with [`DynSigner`].
    pub fn create_upgraded(signer: DynSigner) -> Self {
        Self::Upgraded(signer)
    }

    /// Create a new [`EoaKind`] with [`CreatableAccount`].
    pub fn create_prep() -> Self {
        Self::Prep(None)
    }

    /// Returns a reference to the inner [`DynSigner`] when dealing with an upgraded account.
    ///
    /// # Panics
    ///
    /// This will panic if it's not an upgraded account.
    pub fn root_signer(&self) -> &DynSigner {
        match self {
            EoaKind::Upgraded(dyn_signer) => dyn_signer,
            EoaKind::Prep { .. } => {
                panic!("eoa is not an upgraded account")
            }
        }
    }

    /// Whether self is a PREP account.
    pub fn is_prep(&self) -> bool {
        matches!(self, Self::Prep { .. })
    }

    /// Returns [`Address`].
    ///
    /// # Panics
    ///
    /// It will panic if the account has not been yet created when dealing with
    /// [`CreatableAccount`].
    pub fn address(&self) -> Address {
        match self {
            EoaKind::Upgraded(dyn_signer) => dyn_signer.address(),
            EoaKind::Prep(account) => {
                account.as_ref().expect("prep not calculated yet").prep.address
            }
        }
    }
}

/// An account that can be used to send intents.
pub struct MockAccount {
    pub address: Address,
    pub key: KeyWith712Signer,
}

impl MockAccount {
    /// Creates a new random account by going through PREP flow.
    pub async fn new(env: &Environment) -> eyre::Result<Self> {
        Self::with_key(env, B256::random()).await
    }

    /// Creates a new account by going through PREP flow with the given key.
    pub async fn with_key(env: &Environment, key: B256) -> eyre::Result<Self> {
        let key = KeyWith712Signer::mock_admin_with_key(KeyType::Secp256k1, key).unwrap().unwrap();

        let PrepareCreateAccountResponse { context, address, .. } = env
            .relay_endpoint
            .prepare_create_account(PrepareCreateAccountParameters {
                capabilities: PrepareCreateAccountCapabilities {
                    authorize_keys: vec![key.to_authorized(None).await?],
                    delegation: env.delegation,
                },
                chain_id: env.chain_id,
            })
            .await
            .unwrap();

        // Using ETH for payments
        env.provider.anvil_set_balance(address, U256::from(100e18)).await?;

        let signature = key.id_sign(address).await.unwrap();

        env.relay_endpoint
            .create_account(CreateAccountParameters {
                context,
                signatures: vec![KeySignature {
                    public_key: key.publicKey.clone(),
                    key_type: key.keyType,
                    value: signature.as_bytes().into(),
                    prehash: false,
                }],
            })
            .await
            .unwrap();

        let PrepareCallsResponse { context, digest, .. } = env
            .relay_endpoint
            .prepare_calls(PrepareCallsParameters {
                calls: vec![Call {
                    to: env.erc20,
                    value: U256::ZERO,
                    data: MockErc20::mintCall { a: address, val: U256::from(100e18) }
                        .abi_encode()
                        .into(),
                }],
                chain_id: env.chain_id,
                from: Some(address),
                capabilities: PrepareCallsCapabilities {
                    authorize_keys: vec![],
                    meta: Meta { fee_payer: None, fee_token: Address::ZERO, nonce: None },
                    pre_calls: vec![],
                    pre_call: false,
                    revoke_keys: vec![],
                },
                key: Some(key.to_call_key()),
            })
            .await
            .unwrap();

        let signature = key.sign_payload_hash(digest).await?;

        let bundle_id = send_prepared_calls(env, &key, signature, context).await.unwrap();

        // Wait for bundle to not be pending.
        let status = await_calls_status(env, bundle_id).await?;

        assert!(status.status.is_final());

        Ok(MockAccount { address, key })
    }

    /// Prepares a simple transaction from the account which is ready to be sent to the transacton
    /// service.
    pub async fn prepare_tx(&self, env: &Environment) -> RelayTransaction {
        let PrepareCallsResponse { mut context, digest, .. } = env
            .relay_endpoint
            .prepare_calls(PrepareCallsParameters {
                calls: vec![],
                chain_id: env.chain_id,
                from: Some(self.address),
                capabilities: PrepareCallsCapabilities {
                    authorize_keys: vec![],
                    meta: Meta { fee_payer: None, fee_token: env.erc20, nonce: None },
                    pre_calls: vec![],
                    pre_call: false,
                    revoke_keys: vec![],
                },
                key: Some(self.key.to_call_key()),
            })
            .await
            .unwrap();

        context.quote_mut().unwrap().ty_mut().intent.signature = Signature {
            innerSignature: self.key.sign_payload_hash(digest).await.unwrap(),
            keyHash: self.key.key_hash(),
            prehash: false,
        }
        .abi_encode_packed()
        .into();

        RelayTransaction::new(context.take_quote().unwrap(), None)
    }
}
