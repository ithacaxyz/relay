use alloy::providers::Provider;
use eyre::Result;
use relay::{
    metrics::periodic::{BalanceCollector, MetricCollector, format_units_f64},
    types::IERC20::IERC20Instance,
};

use crate::e2e::environment::Environment;

#[tokio::test(flavor = "multi_thread")]
async fn balance_collector() -> Result<()> {
    let env = Environment::setup_multi_chain(3).await?;

    BalanceCollector::new(env.funder, env.relay_handle.chains.clone()).collect().await?;
    let output = env.relay_handle.metrics.render();

    for chain in env.relay_handle.chains.chains_iter() {
        let (native_symbol, native_decimals) = chain
            .native_symbol()
            .zip(chain.assets().native().map(|(_, a)| a.decimals))
            .unwrap_or(("ETH", 18));

        for signer in chain.signer_addresses() {
            let expected_metric = format!(
                r#"signer_balance{{address="{}",chain_id="{}",symbol="{}"}} {}"#,
                signer.to_checksum(None),
                chain.id(),
                native_symbol,
                format_units_f64(chain.provider().get_balance(signer).await?, native_decimals)?
            );
            assert!(output.contains(&expected_metric));
        }

        for (uid, token) in chain.assets().fee_token_iter_sorted() {
            let balance = if token.address.is_zero() {
                chain.provider().get_balance(env.funder).await?
            } else {
                IERC20Instance::new(token.address, chain.provider())
                    .balanceOf(env.funder)
                    .call()
                    .await?
            };
            let expected_metric = format!(
                r#"funder_balance{{address="{}",chain_id="{}",uid="{}"}} {}"#,
                env.funder.to_checksum(None),
                chain.id(),
                uid,
                format_units_f64(balance, token.decimals)?
            );
            assert!(output.contains(&expected_metric));
        }
    }

    Ok(())
}
