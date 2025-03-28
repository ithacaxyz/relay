use super::{
    cases::{prep_account, upgrade_account},
    check_bundle,
    environment::Environment,
    prepare_calls,
};
use alloy::{
    eips::eip7702::SignedAuthorization,
    primitives::{Address, U256},
    sol_types::SolValue,
};
use eyre::WrapErr;
use futures_util::future::{join_all, try_join_all};
use relay::{
    signers::DynSigner,
    types::{
        Call, KeyWith712Signer, Signature, UserOp,
        rpc::{AuthorizeKey, RevokeKey},
    },
};

/// Represents the expected outcome of a test case execution
#[derive(Debug, Default)]
#[allow(dead_code)]
pub enum ExpectedOutcome {
    /// Test should pass completely
    #[default]
    Pass,
    /// Test should fail at fee estimation
    FailEstimate,
    /// Test should fail when sending the action
    FailSend,
    /// Transaction should revert on-chain
    TxRevert,
    /// UserOp should fail but transaction succeeds
    FailUserOp,
}

impl ExpectedOutcome {
    #[allow(dead_code)]
    pub fn passed(&self) -> bool {
        matches!(self, ExpectedOutcome::Pass)
    }
    pub fn failed_estimate(&self) -> bool {
        matches!(self, ExpectedOutcome::FailEstimate)
    }
    pub fn failed_send(&self) -> bool {
        matches!(self, ExpectedOutcome::FailSend)
    }
    pub fn reverted_tx(&self) -> bool {
        matches!(self, ExpectedOutcome::TxRevert)
    }
    pub fn failed_user_op(&self) -> bool {
        matches!(self, ExpectedOutcome::FailUserOp)
    }
}

/// Represents the type of authorization needed for a test case
#[derive(Debug, Clone)]
pub enum AuthKind {
    /// Use sequential nonce for authorization
    Auth,
    /// Use specific parameters for authorization
    ModifiedAuth { signer: Option<DynSigner>, nonce: Option<u64> },
}

impl AuthKind {
    /// Return [`AuthKind::ModifiedAuth`] with a specified nonce.
    pub fn modified_nonce(nonce: u64) -> Self {
        Self::ModifiedAuth { signer: None, nonce: Some(nonce) }
    }

    /// Return [`AuthKind::ModifiedAuth`] with a specified signer.
    pub fn modified_signer(signer: DynSigner) -> Self {
        Self::ModifiedAuth { signer: Some(signer), nonce: None }
    }

    /// Return nonce if [`AuthKind::ModifiedAuth`] has it, otherwise `None`
    pub fn nonce(&self) -> Option<u64> {
        match self {
            AuthKind::Auth => None,
            AuthKind::ModifiedAuth { nonce, .. } => *nonce,
        }
    }

    /// Return signer if [`AuthKind::ModifiedAuth`] has it, otherwise `None`
    pub fn signer(&self) -> Option<&DynSigner> {
        match self {
            AuthKind::Auth => None,
            AuthKind::ModifiedAuth { signer, .. } => signer.as_ref(),
        }
    }

    pub async fn sign(&self, env: &Environment, nonce: u64) -> eyre::Result<SignedAuthorization> {
        let auth_struct = alloy::eips::eip7702::Authorization {
            chain_id: U256::from(0),
            address: env.delegation,
            nonce: self.nonce().unwrap_or(nonce),
        };
        let auth_hash = auth_struct.signature_hash();

        Ok(auth_struct.into_signed(
            self.signer()
                .unwrap_or(env.eoa.root_signer())
                .sign_hash(&auth_hash)
                .await
                .wrap_err("Auth signing failed")?,
        ))
    }
}

/// Context for executing a test transaction
#[derive(Debug, Default)]
pub struct TxContext<'a> {
    /// List of calls to execute
    pub calls: Vec<Call>,
    /// Expected outcome of the transaction
    pub expected: ExpectedOutcome,
    /// Optional authorization.
    pub auth: Option<AuthKind>,
    /// Optional Key that will sign the UserOp
    pub key: Option<&'a KeyWith712Signer>,
    /// List of keys to authorize that will be converted to calls on top of the UserOp.
    pub authorization_keys: Vec<&'a KeyWith712Signer>,
    /// List of keys to revoke that will be converted to calls on bottom of the UserOp.
    pub revoke_keys: Vec<&'a KeyWith712Signer>,
    /// Fee token to be used
    #[allow(dead_code)]
    pub fee_token: Address,
    /// Optional array of pre-ops to be executed before the UserOp.
    pub pre_ops: Vec<TxContext<'a>>,
    /// Optional nonce to be used.
    pub nonce: Option<U256>,
}

impl TxContext<'_> {
    /// Creates a PREPAccount from the first [`TxContext`] of a test case.
    pub async fn prep_account(
        &mut self,
        env: &mut Environment,
        tx_num: usize,
    ) -> Result<(), eyre::Error> {
        let tx_hash =
            prep_account(env, &self.calls, &self.authorization_keys, &self.pre_ops, tx_num).await;

        // Check test expectations
        let op_nonce = U256::ZERO; // first transaction
        check_bundle(tx_hash, self, tx_num, None, op_nonce, &*env).await?;

        Ok(())
    }

    /// Upgrades an account from the first [`TxContext`] of a test case.
    ///
    /// Since upgrade account cannot bundle a list of [`Call`], it returns them so they can be
    /// bundled for the following transaction.
    pub async fn upgrade_account(
        &self,
        env: &Environment,
        tx_num: usize,
    ) -> Result<Vec<Call>, eyre::Error> {
        let pre_ops = build_pre_ops(env, &self.pre_ops, tx_num).await?;
        let (tx_hash, authorization) = upgrade_account(
            env,
            &self.authorization_keys(Some(env.eoa.address())).await?,
            self.auth.clone().expect("should have"),
            pre_ops,
        )
        .await
        .map_or_else(|e| (Err(e), None), |(a, b)| (Ok(a), Some(b)));

        // Check test expectations
        let op_nonce = U256::ZERO; // first transaction
        check_bundle(tx_hash, self, tx_num, authorization, op_nonce, env).await?;

        Ok(self.calls.clone())
    }

    /// Returns authorization keys as a list of [`AuthorizeKey`].
    pub async fn authorization_keys(
        &self,
        account: Option<Address>,
    ) -> eyre::Result<Vec<AuthorizeKey>> {
        try_join_all(self.authorization_keys.iter().map(async |k| k.to_authorized(account).await))
            .await
    }

    /// Returns keys as a list of [`RevokeKey`].
    pub fn revoke_keys(&self) -> Vec<RevokeKey> {
        self.revoke_keys.iter().map(|k| k.to_revoked()).collect()
    }
}

pub async fn build_pre_ops<'a>(
    env: &Environment,
    pre_ops: &[TxContext<'a>],
    tx_num: usize,
) -> eyre::Result<Vec<UserOp>> {
    let pre_ops = join_all(pre_ops.iter().map(|tx| async move {
        let signer = tx.key.expect("userop should have a key");
        let (signature, quote) =
            prepare_calls(tx_num, tx, signer, env, true).await.unwrap().unwrap();
        let mut op = quote.ty().op.clone();
        op.signature =
            Signature { innerSignature: signature, keyHash: signer.key_hash(), prehash: false }
                .abi_encode_packed()
                .into();
        op
    }))
    .await;

    Ok(pre_ops)
}

alloy::sol! {
    #[sol(rpc)]
    interface MockErc20 {
        constructor(string memory name_, string memory symbol_, uint8 decimals_) {
            _name = name_;
            _symbol = symbol_;
            _decimals = decimals_;
            _nameHash = keccak256(bytes(name_));
        }
        function mint(address a, uint256 val) external;
        function transfer(address recipient, uint256 amount);
    }
}
