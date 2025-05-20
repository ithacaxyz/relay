use super::{
    await_calls_status, cases::upgrade_account, environment::Environment, prepare_calls,
    send_prepared_calls,
};
use alloy::{
    eips::eip7702::{SignedAuthorization, constants::EIP7702_DELEGATION_DESIGNATOR},
    primitives::{Address, U256},
    providers::Provider,
    sol_types::SolValue,
};
use derive_more::Debug;
use eyre::WrapErr;
use futures_util::future::{BoxFuture, join_all, try_join_all};
use relay::{
    signers::DynSigner,
    types::{
        Call, KeyWith712Signer, ORCHESTRATOR_NO_ERROR,
        OrchestratorContract::UserOpExecuted,
        PreOp, Signature,
        rpc::{AuthorizeKey, BundleId, CallStatusCode, RevokeKey},
    },
};

/// Alias type of a boxed async closure capturing [`Environment`] and [`TxContext`] for checking the
/// outcome of a successful transaction.
pub type PostTxCheck =
    Box<dyn for<'a> Fn(&'a Environment, &TxContext<'_>) -> BoxFuture<'a, eyre::Result<()>>>;

/// Represents the expected outcome of a test case execution
#[derive(Debug, Default, Clone, Copy)]
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
    /// Optional authorization. Used only for upgrading existing EOAs.
    pub auth: Option<AuthKind>,
    /// Optional Key that will sign the UserOp
    pub key: Option<&'a KeyWith712Signer>,
    /// List of keys to authorize that will be converted to calls on top of the UserOp.
    pub authorization_keys: Vec<&'a KeyWith712Signer>,
    /// List of keys to revoke that will be converted to calls on bottom of the UserOp.
    pub revoke_keys: Vec<&'a KeyWith712Signer>,
    /// Fee token to be used
    pub fee_token: Option<Address>,
    /// Optional array of pre-ops to be executed before the UserOp.
    pub pre_ops: Vec<TxContext<'a>>,
    /// Optional nonce to be used.
    pub nonce: Option<U256>,
    /// Optional checks after a successful transaction.
    #[debug(skip)]
    pub post_tx: Vec<PostTxCheck>,
}

impl TxContext<'_> {
    /// Upgrades an account from the first [`TxContext`] of a test case.
    ///
    /// Since upgrade account cannot bundle a list of [`Call`], it returns them so they can be
    /// bundled for the following transaction.
    pub async fn upgrade_account(
        &self,
        env: &Environment,
        tx_num: usize,
    ) -> Result<Vec<Call>, eyre::Error> {
        let (tx_hash, authorization) = upgrade_account(
            env,
            &self.authorization_keys(Some(env.eoa.address())).await?,
            self.auth.clone().expect("should have"),
        )
        .await
        .map_or_else(|e| (Err(e), None), |(a, b)| (Ok(a), Some(b)));

        // Check test expectations
        let op_nonce = U256::ZERO; // first transaction
        self.check_bundle(tx_hash, tx_num, authorization, op_nonce, env).await?;

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

    /// Processes a single transaction, returning error on a unexpected failure.
    ///
    /// The process follows these steps:
    /// 1. Obtains a signed quote and UserOp signature from [`prepare_calls`].
    /// 2. Submits and verifies execution with [`send_prepared_calls`].
    ///    - Sends the prepared calls and signature to the relay
    ///    - Handles expected send failures
    ///    - Retrieves and checks transaction receipt
    ///    - Verifies transaction status matches expectations
    ///    - Confirms UserOp success by checking nonce invalidation
    pub async fn process(self, tx_num: usize, env: &Environment) -> eyre::Result<()> {
        let signer = self.key.expect("should have key");

        let Some((signature, context)) = prepare_calls(tx_num, &self, signer, env, false).await?
        else {
            // We had an expected failure so we should exit.
            return Ok(());
        };

        let op_nonce = context.quote().as_ref().unwrap().ty().op.nonce;

        // Submit signed call
        let bundle = send_prepared_calls(env, signer, signature, context).await;

        self.check_bundle(bundle, tx_num, None, op_nonce, env).await
    }

    /// Checks that the submitted bundle has had the expected test outcome.
    pub async fn check_bundle(
        &self,
        bundle_id: eyre::Result<BundleId>,
        tx_num: usize,
        authorization: Option<SignedAuthorization>,
        _op_nonce: U256,
        env: &Environment,
    ) -> Result<(), eyre::Error> {
        match bundle_id {
            Ok(bundle_id) => {
                let calls_status =
                    await_calls_status(env, bundle_id).await.wrap_err("Failed to get receipt")?;
                if self.expected.failed_send() && calls_status.status != CallStatusCode::Failed {
                    return Err(eyre::eyre!(
                        "Send action {tx_num} passed when it should have failed.",
                    ));
                } else if !self.expected.failed_send()
                    && calls_status.status == CallStatusCode::Failed
                {
                    return Err(eyre::eyre!(
                        "Send action {tx_num} failed when it should have passed.",
                    ));
                } else if self.expected.failed_send()
                    && calls_status.status == CallStatusCode::Failed
                {
                    return Ok(());
                }

                let receipt = &calls_status.receipts[0];
                if receipt.status.coerce_status() {
                    if self.expected.reverted_tx() {
                        return Err(eyre::eyre!(
                            "Transaction {tx_num} passed when it should have reverted.",
                        ));
                    }
                } else if !self.expected.reverted_tx() {
                    return Err(eyre::eyre!("Transaction {tx_num} failed: {receipt:#?}"));
                }

                if authorization.is_some()
                    && env.provider.get_code_at(env.eoa.address()).await?
                        != [&EIP7702_DELEGATION_DESIGNATOR[..], env.delegation.as_slice()].concat()
                {
                    return Err(eyre::eyre!("Transaction {tx_num} failed to delegate"));
                }

                // UserOp has succeeded if the nonce has been invalidated.
                let success = if let Some(event) = receipt.decoded_log::<UserOpExecuted>() {
                    event.incremented && event.err == ORCHESTRATOR_NO_ERROR
                } else {
                    false
                };
                if success && self.expected.failed_user_op() {
                    return Err(eyre::eyre!("UserOp {tx_num} passed when it should have failed."));
                } else if !success && !self.expected.failed_user_op() {
                    return Err(eyre::eyre!(
                        "Transaction succeeded but UserOp failed for transaction {tx_num}",
                    ));
                }

                // Make any additional custom checks
                for post_tx_check in &self.post_tx {
                    post_tx_check(env, self).await?
                }
            }
            Err(err) => {
                if self.expected.failed_send() {
                    return Ok(());
                }
                return Err(eyre::eyre!("Send error for transaction {tx_num}: {err}"));
            }
        };
        Ok(())
    }
}

pub async fn build_pre_ops<'a>(
    env: &Environment,
    pre_ops: &[TxContext<'a>],
    tx_num: usize,
) -> eyre::Result<Vec<PreOp>> {
    let pre_ops = join_all(pre_ops.iter().map(|tx| async move {
        let signer = tx.key.expect("userop should have a key");
        let (signature, context) =
            prepare_calls(tx_num, tx, signer, env, true).await.unwrap().unwrap();
        let mut op = context.take_preop().unwrap();
        op.signature =
            Signature { innerSignature: signature, keyHash: signer.key_hash(), prehash: false }
                .abi_encode_packed()
                .into();
        op
    }))
    .await;

    Ok(pre_ops)
}

/// Helper macro for checking the outcome of a successful transaction.
#[macro_export]
macro_rules! check {
    (| $env:ident, $tx:ident | $body:block) => {
        vec![Box::new(move |$env, $tx| Box::pin(async move { $body }))]
    };
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

alloy::sol! {
    #[sol(rpc)]
    interface MockErc721 {
        function mint() external;
    }
}
