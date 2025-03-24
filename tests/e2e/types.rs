use std::ops::Deref;

use super::{
    cases::{prep_account, upgrade_account},
    check_bundle,
    environment::{Environment, mint_erc20s},
};
use MockErc20::MockErc20Calls;
use alloy::{
    eips::eip7702::SignedAuthorization,
    primitives::{Address, Bytes, TxKind, U256},
    providers::Provider,
    rpc::types::TransactionRequest,
    sol,
    sol_types::{SolCall, SolValue},
};
use eyre::WrapErr;
use relay::{
    signers::{DynSigner, P256Signer},
    types::{Call, Key, KeyType, KeyWith712Signer, rpc::AuthorizeKey},
};

/// Represents the expected outcome of a test case execution
#[derive(Debug, Default)]
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
            AuthKind::ModifiedAuth { signer, nonce } => *nonce,
        }
    }

    /// Return signer if [`AuthKind::ModifiedAuth`] has it, otherwise `None`
    pub fn signer(&self) -> Option<&DynSigner> {
        match self {
            AuthKind::Auth => None,
            AuthKind::ModifiedAuth { signer, nonce } => signer.as_ref(),
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
    pub authorization_keys: Vec<AuthorizeKey>,
    /// Fee token to be used
    pub fee_token: Address,
}

impl TxContext<'_> {
    /// Creates a PREPAccount from the first [`TxContext`] of a test case.
    pub async fn prep_account(
        &mut self,
        env: &mut Environment,
        tx_num: usize,
    ) -> Result<(), eyre::Error> {
        /// Ensure that there is always at least one admin key.
        self.authorization_keys.push(env.eoa.prep_signer().to_authorized());

        // If we add more authorization_keys, the EOA address init data will be different, so we
        // need to mint native and fake tokens into our generated EOA.
        let before = env.eoa.address();
        let tx_hash = prep_account(env, &self.calls, &self.authorization_keys).await;
        if before != env.eoa.address() {
            mint_erc20s(&[env.erc20, env.erc20_alt], &[env.eoa.address()], &env.provider).await?;
            env.provider
                .send_transaction(TransactionRequest {
                    to: Some(TxKind::Call(env.eoa.address())),
                    value: Some(U256::from(100e18)),
                    ..Default::default()
                })
                .await?
                .get_receipt()
                .await?;
        }

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
        let (tx_hash, authorization) =
            upgrade_account(env, &self.authorization_keys, self.auth.clone().expect("should have"))
                .await
                .map_or_else(|e| (Err(e), None), |(a, b)| (Ok(a), Some(b)));

        // Check test expectations
        let op_nonce = U256::ZERO; // first transaction
        check_bundle(tx_hash, self, tx_num, authorization, op_nonce, env).await?;

        Ok(self.calls.clone())
    }
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
