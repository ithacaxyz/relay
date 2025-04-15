use super::{TxContext, environment::Environment, process_tx};
use relay::types::Call;
use strum::EnumIter;

/// Test configuration that will prepare the desired [`Environment`] before a run.
#[derive(Debug, Clone, Copy)]
pub struct TestConfig {
    /// Account configuration.
    pub account: AccountConfig,
    /// Payment method configuration.
    pub payment: PaymentConfig,
}

impl TestConfig {
    /// Runs the test for a specific configuration.
    pub async fn run<'a, F>(&self, build_txs: F) -> eyre::Result<()>
    where
        F: Fn(&Environment) -> Vec<TxContext<'a>> + Send + Sync,
    {
        // Setup the initial environment based on account type.
        let mut env = self.account.setup_environment().await?;

        // Apply native or ERC20 payment method
        env = self.payment.apply(env);

        // Generate transactions from test case
        let txs = build_txs(&env);

        let mut first_tx_calls = Vec::new();
        for (tx_num, mut tx) in txs.into_iter().enumerate() {
            if tx_num == 0 {
                // This should only really returns calls with upgraded accounts.
                first_tx_calls = self.account.handle_first_tx(&mut env, tx_num, &mut tx).await?;
            } else {
                // Prepend any extra calls from the first transaction.
                tx.calls.splice(0..0, first_tx_calls.drain(..));

                process_tx(tx_num, tx, &env).await?;
            }
        }

        Ok(())
    }
}

impl From<(AccountConfig, PaymentConfig)> for TestConfig {
    fn from(value: (AccountConfig, PaymentConfig)) -> Self {
        Self { account: value.0, payment: value.1 }
    }
}

/// EOA smart account to be used on a [`Environment`].
#[derive(Debug, Clone, Copy, EnumIter)]
pub enum AccountConfig {
    Prep,
    Upgraded,
}

impl AccountConfig {
    /// Set up the environment based on the account type.
    pub async fn setup_environment(self) -> eyre::Result<Environment> {
        match self {
            AccountConfig::Prep => Environment::setup_with_prep().await,
            AccountConfig::Upgraded => Environment::setup_with_upgraded().await,
        }
    }

    /// Perform the first-transaction handling.
    ///
    /// If it's an upgraded account, returns the list of [`Call`] that should be prepended on the
    /// next transaction, since it does not support bundling.
    pub async fn handle_first_tx(
        self,
        env: &mut Environment,
        tx_num: usize,
        tx: &mut TxContext<'_>,
    ) -> eyre::Result<Vec<Call>> {
        match self {
            AccountConfig::Prep => {
                tx.prep_account(env, tx_num).await?;
                Ok(vec![])
            }
            AccountConfig::Upgraded => tx.upgrade_account(env, tx_num).await,
        }
    }
}

/// Payment method be used on a user op.
#[derive(Debug, Clone, Copy, EnumIter)]
pub enum PaymentConfig {
    Native,
    ERC20,
}

impl PaymentConfig {
    /// Modify the environment based on the payment method.
    fn apply(self, env: Environment) -> Environment {
        match self {
            PaymentConfig::ERC20 => env,
            PaymentConfig::Native => env.with_native_payment(),
        }
    }
}
