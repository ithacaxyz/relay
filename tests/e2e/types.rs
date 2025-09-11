use std::ops::Not;

use super::{await_calls_status, environment::Environment, prepare_calls};
use alloy::{
    eips::eip7702::{SignedAuthorization, constants::EIP7702_DELEGATION_DESIGNATOR},
    primitives::{Address, B256, U256},
    providers::Provider,
    sol_types::SolValue,
};
use derive_more::Debug;
use eyre::WrapErr;
use futures_util::future::{BoxFuture, join_all};
use relay::{
    rpc::RelayApiClient,
    signers::DynSigner,
    types::{
        Call, KeyWith712Signer, ORCHESTRATOR_NO_ERROR,
        OrchestratorContract::IntentExecuted,
        Signature, SignedCall,
        rpc::{AuthorizeKey, BundleId, CallStatusCode, RevokeKey, SendPreparedCallsParameters},
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
    /// Intent should fail but transaction succeeds
    FailIntent,
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
    pub fn failed_intent(&self) -> bool {
        matches!(self, ExpectedOutcome::FailIntent)
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
            chain_id: U256::ZERO,
            address: env.delegation,
            nonce: self.nonce().unwrap_or(nonce),
        };
        let auth_hash = auth_struct.signature_hash();

        Ok(auth_struct.into_signed(
            self.signer()
                .unwrap_or(&env.eoa)
                .sign_hash(&auth_hash)
                .await
                .wrap_err("Auth signing failed")?,
        ))
    }
}

/// Context for executing a test transaction
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct TxContext<'a> {
    /// List of calls to execute.
    pub calls: Vec<Call>,
    /// Expected outcome of the transaction.
    pub expected: ExpectedOutcome,
    /// Optional authorization. Used only for upgrading existing EOAs.
    pub auth: Option<AuthKind>,
    /// Optional Key that will sign the Intent.
    pub key: Option<&'a KeyWith712Signer>,
    /// Do not include `key` in the `prepareCalls` parameters and use an empty `keyHash`.
    pub omit_call_key: bool,
    /// List of keys to authorize that will be converted to calls on top of the Intent.
    pub authorization_keys: Vec<&'a KeyWith712Signer>,
    /// List of keys to revoke that will be converted to calls on bottom of the Intent.
    pub revoke_keys: Vec<&'a KeyWith712Signer>,
    /// Fee token to be used
    pub fee_token: Option<Address>,
    /// Optional array of precalls to be executed before the Intent.
    pub pre_calls: Vec<TxContext<'a>>,
    /// Optional nonce to be used.
    pub nonce: Option<U256>,
    /// Optional checks after a successful transaction.
    #[debug(skip)]
    pub post_tx: Vec<PostTxCheck>,
}

impl TxContext<'_> {
    /// Returns authorization keys as a list of [`AuthorizeKey`].
    pub fn authorization_keys(&self) -> Vec<AuthorizeKey> {
        self.authorization_keys.iter().map(|k| k.to_authorized()).collect()
    }

    /// Returns keys as a list of [`RevokeKey`].
    pub fn revoke_keys(&self) -> Vec<RevokeKey> {
        self.revoke_keys.iter().map(|k| k.to_revoked()).collect()
    }

    /// Processes a single transaction, returning error on a unexpected failure.
    ///
    /// The process follows these steps:
    /// 1. Obtains a signed quote and Intent signature from [`prepare_calls`].
    /// 2. Submits and verifies execution with [`send_prepared_calls`].
    ///    - Sends the prepared calls and signature to the relay
    ///    - Handles expected send failures
    ///    - Retrieves and checks transaction receipt
    ///    - Verifies transaction status matches expectations
    ///    - Confirms Intent success by checking nonce invalidation
    pub async fn process(self, tx_num: usize, env: &Environment) -> eyre::Result<()> {
        let signer = self.key.expect("should have key");

        let Some((signature, context)) = prepare_calls(tx_num, &self, signer, env, false).await?
        else {
            // We had an expected failure so we should exit.
            return Ok(());
        };

        // todo(onbjerg): this assumes a single intent
        let intent_nonce = context.quote().as_ref().unwrap().ty().quotes[0].intent.nonce();

        // Submit signed call
        let bundle = env
            .relay_endpoint
            .send_prepared_calls(SendPreparedCallsParameters {
                capabilities: Default::default(),
                context,
                key: self.omit_call_key.not().then_some(signer.to_call_key()),
                signature,
            })
            .await
            .map(|bundle| bundle.id)
            .map_err(Into::into);

        self.check_bundle(bundle, tx_num, None, intent_nonce, env).await
    }

    /// Checks that the submitted bundle has had the expected test outcome.
    pub async fn check_bundle(
        &self,
        bundle_id: eyre::Result<BundleId>,
        tx_num: usize,
        authorization: Option<SignedAuthorization>,
        _intent_nonce: U256,
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
                    && env.provider().get_code_at(env.eoa.address()).await?
                        != [&EIP7702_DELEGATION_DESIGNATOR[..], env.delegation.as_slice()].concat()
                {
                    return Err(eyre::eyre!("Transaction {tx_num} failed to delegate"));
                }

                // Intent has succeeded if the nonce has been invalidated.
                let success = if let Some(event) = receipt.decoded_log::<IntentExecuted>() {
                    event.incremented && event.err == ORCHESTRATOR_NO_ERROR
                } else {
                    false
                };
                if success && self.expected.failed_intent() {
                    return Err(eyre::eyre!("Intent {tx_num} passed when it should have failed."));
                } else if !success && !self.expected.failed_intent() {
                    return Err(eyre::eyre!(
                        "Transaction succeeded but Intent failed for transaction {tx_num}",
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

pub async fn build_pre_calls<'a>(
    env: &Environment,
    pre_calls: &[TxContext<'a>],
    tx_num: usize,
) -> eyre::Result<Vec<SignedCall>> {
    let pre_calls = join_all(pre_calls.iter().map(|tx| async move {
        let signer = tx.key.expect("intent should have a key");
        let (signature, context) =
            prepare_calls(tx_num, tx, signer, env, true).await.unwrap().unwrap();
        let mut intent = context.take_precall().unwrap();
        intent.signature = Signature {
            innerSignature: signature,
            keyHash: if tx.omit_call_key { B256::ZERO } else { signer.key_hash() },
            prehash: false,
        }
        .abi_encode_packed()
        .into();
        intent
    }))
    .await;

    Ok(pre_calls)
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
        function approve(address spender, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
    }
}

alloy::sol! {
    #[sol(rpc)]
    interface MockErc721 {
        function mint() external;
    }
}
