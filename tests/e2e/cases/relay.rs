use crate::e2e::environment::Environment;
use relay::rpc::RelayApiClient;
use semver::{self, Version};

#[tokio::test]
async fn versioned_contracts() -> eyre::Result<()> {
    let env = Environment::setup_with_prep().await?;

    let capabilities = env.relay_endpoint.get_capabilities(vec![env.chain_id]).await?;

    Version::parse(
        capabilities.chain(env.chain_id).contracts.orchestrator.version.as_ref().unwrap(),
    )
    .unwrap();
    Version::parse(
        capabilities
            .chain(env.chain_id)
            .contracts
            .delegation_implementation
            .version
            .as_ref()
            .unwrap(),
    )
    .unwrap();

    Ok(())
}
