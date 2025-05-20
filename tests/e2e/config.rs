use super::{TxContext, cases::prep_account, environment::Environment};
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

        let mut txs = txs.into_iter().enumerate().peekable();
        while let Some((tx_num, mut tx)) = txs.next() {
            // The account needs to be set up in the very first transaction. PREP supports bundling
            // calls with it, while upgrading an existing EOA does not.
            if tx_num == 0 {
                match self.account {
                    AccountConfig::Prep => {
                        // If a signer is not defined, takes the first authorized key from the tx
                        // context.
                        tx.key = Some(tx.key.as_ref().unwrap_or(&tx.authorization_keys[0]));
                        prep_account(&mut env, &std::mem::take(&mut tx.authorization_keys)).await?;
                    }
                    AccountConfig::Upgraded => {
                        // Since upgrade account cannot bundle a list of Call, it returns them so
                        // they can be bundled for the following transaction.
                        let mut calls = tx.upgrade_account(&env, tx_num).await?;
                        if let Some((_, next_tx)) = txs.peek_mut() {
                            next_tx.calls.splice(0..0, calls.drain(..));
                        }
                        continue;
                    }
                }
            }
            tx.process(tx_num, &env).await?;
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
}

/// Payment method be used on a intent.
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
