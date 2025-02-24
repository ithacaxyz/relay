use super::environment::Environment;
use alloy::{
    eips::eip7702::SignedAuthorization,
    primitives::{Address, U256},
    sol,
};
use eyre::WrapErr;
use relay::{
    signers::{DynSigner, P256Signer},
    types::{Call, Key, KeyType, KeyWith712Signer},
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
#[derive(Debug)]
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
                .unwrap_or(&env.eoa_signer)
                .sign_hash(&auth_hash)
                .await
                .wrap_err("Auth signing failed")?,
        ))
    }
}

/// Context for executing a test transaction
#[derive(Debug, Default)]
pub struct TxContext {
    /// List of calls to execute
    pub calls: Vec<Call>,
    /// Expected outcome of the transaction
    pub expected: ExpectedOutcome,
    /// Optional authorization.
    pub auth: Option<AuthKind>,
    /// Optional Key.
    pub key: Option<KeyWith712Signer>,
}

sol! {
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
