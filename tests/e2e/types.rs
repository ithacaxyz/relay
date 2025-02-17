use alloy::sol;
use relay::types::Call;

/// Represents the expected outcome of a test case execution
#[derive(Debug)]
pub enum ExpectedOutcome {
    /// Test should pass completely
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
    /// Use specific nonce value for authorization
    AuthWithNonce(u64),
}

impl AuthKind {
    /// Return nonce if [`AuthKind::AuthWithNonce`], otherwise `None`
    pub fn nonce(&self) -> Option<u64> {
        match self {
            AuthKind::Auth => None,
            AuthKind::AuthWithNonce(nonce) => Some(*nonce),
        }
    }
}

/// Context for executing a test transaction
#[derive(Debug)]
pub struct TxContext {
    /// List of calls to execute
    pub calls: Vec<Call>,
    /// Expected outcome of the transaction
    pub expected: ExpectedOutcome,
    /// Optional authorization.
    pub auth: Option<AuthKind>,
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

sol! {
    #[sol(rpc)]
    interface Delegation {
        event NonceInvalidated(uint256 nonce);
    }
}
