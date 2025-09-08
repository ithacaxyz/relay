use std::time::Duration;

use crate::e2e::environment::Environment;
use alloy::{primitives::U64, providers::Provider};
use relay::{rpc::RelayApiClient, types::Eip712Contract::Eip712ContractInstance};
use semver::{self, Version};

#[tokio::test]
async fn versioned_contracts() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let capabilities =
        env.relay_endpoint.get_capabilities(Some(vec![U64::from(env.chain_id())])).await?;

    for provider in &env.providers {
        let chain_id = provider.get_chain_id().await?;

        let get_version = |address| async move {
            eyre::Ok(
                Version::parse(
                    &Eip712ContractInstance::new(address, provider.clone())
                        .eip712Domain()
                        .call()
                        .await?
                        .version,
                )
                .ok(),
            )
        };

        assert_eq!(
            get_version(env.config.orchestrator).await?,
            capabilities.chain(chain_id).contracts.orchestrator.version
        );

        for legacy in &env.config.legacy_orchestrators {
            let orchestrator = get_version(legacy.orchestrator).await?;
            let simulator = get_version(legacy.simulator).await?;
            assert!(
                capabilities
                    .chain(chain_id)
                    .contracts
                    .legacy_orchestrators
                    .iter()
                    .any(|legacy| legacy.orchestrator.version == orchestrator
                        && legacy.simulator.version == simulator)
            );
        }
    }

    Ok(())
}

/// Tests that the relay can be restarted with an updated configuration.
#[tokio::test(flavor = "multi_thread")]
async fn test_relay_restart() -> eyre::Result<()> {
    let mut env = Environment::setup().await?;

    // Get initial relay endpoint to verify it changes
    let initial_endpoint = env.relay_handle.http_url();

    // Test the relay is responsive before restart
    let initial_caps = env.relay_endpoint.get_capabilities(None).await?;
    assert!(!initial_caps.0.is_empty());

    // Restart relay with modified configuration
    let new_fee_recipient = alloy::primitives::Address::random();
    let new_config = env
        .config
        .clone()
        .with_quote_ttl(Duration::from_secs(120))
        .with_fee_recipient(new_fee_recipient)
        .with_port(0); // Use random available port
    env.restart_relay(new_config).await?;

    // Verify the relay endpoint has changed (new server instance)
    let new_endpoint = env.relay_handle.http_url();
    assert_ne!(initial_endpoint, new_endpoint, "Relay endpoint should change after restart");

    // Test the relay is responsive after restart
    let new_caps = env.relay_endpoint.get_capabilities(None).await?;
    assert!(!new_caps.0.is_empty());

    // Verify configuration changes took effect
    assert_eq!(env.config.quote.ttl, Duration::from_secs(120));

    Ok(())
}
