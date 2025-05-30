use super::{AuthKind, TxContext, cases::upgrade_account_lazily, environment::Environment};
use strum::EnumIter;

/// Test configuration that will prepare the desired [`Environment`] before a run.
#[derive(Debug, Clone, Copy)]
pub struct TestConfig {
    /// Payment method configuration.
    pub payment: PaymentConfig,
}

impl TestConfig {
    /// Runs the test for a specific configuration.
    pub async fn run<'a, F>(&self, build_txs: F) -> eyre::Result<()>
    where
        F: Fn(&Environment) -> Vec<TxContext<'a>> + Send + Sync,
    {
        // Setup the initial environment.
        let mut env = Environment::setup().await?;

        // Apply native or ERC20 payment method
        env = self.payment.apply(env);

        // Generate transactions from test case
        let txs = build_txs(&env);

        let txs = txs.into_iter().enumerate().peekable();
        for (tx_num, mut tx) in txs {
            // The account needs to be set up in the very first transaction.
            if tx_num == 0 {
                // If a signer is not defined, takes the first authorized key from the tx
                // context.
                tx.key = Some(tx.key.as_ref().unwrap_or(&tx.authorization_keys[0]));

                // authorization_keys field on the first tx are handled as initialization keys.
                upgrade_account_lazily(
                    &env,
                    &tx.authorization_keys.drain(..).map(|k| k.to_authorized()).collect::<Vec<_>>(),
                    tx.auth.clone().unwrap_or(AuthKind::Auth),
                )
                .await?;
            }
            tx.process(tx_num, &env).await?;
        }

        Ok(())
    }
}

impl From<PaymentConfig> for TestConfig {
    fn from(value: PaymentConfig) -> Self {
        Self { payment: value }
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
