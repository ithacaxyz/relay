use crate::e2e::environment::Environment;
use relay::{cli::Args, spawn::try_spawn_with_args};
use std::{
    env::temp_dir,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
};
use url::Url;

#[tokio::test]
async fn respawn_cli() -> eyre::Result<()> {
    let env = Environment::setup().await?;

    let dir = temp_dir();
    let config = dir.join("relay.yaml");
    let registry = dir.join("registry.yaml");
    let mnemonic = "test test test test test test test test test test test junk";

    for _ in 0..=1 {
        let _ = try_spawn_with_args(
            Args {
                config: config.clone(),
                registry: registry.clone(),
                address: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 0,
                metrics_port: 0,
                max_connections: Default::default(),
                orchestrator: Some(env.orchestrator),
                delegation_proxy: Some(env.delegation),
                simulator: Default::default(),
                endpoints: Some(vec![
                    Url::from_str(&env._anvil.as_ref().unwrap().endpoint()).unwrap(),
                ]),
                fee_recipient: Default::default(),
                quote_ttl: Default::default(),
                rate_ttl: Default::default(),
                constant_rate: Default::default(),
                fee_tokens: Default::default(),
                intent_gas_buffer: Default::default(),
                tx_gas_buffer: Default::default(),
                database_url: Default::default(),
                max_pending_transactions: Default::default(),
                num_signers: Default::default(),
                signers_mnemonic: mnemonic.parse().unwrap(),
                sequencer_endpoints: Default::default(),
                public_node_endpoints: Default::default(),
                config_only: Default::default(),
                priority_fee_percentile: Default::default(),
                banxa_api_url: Url::from_str("https://api.banxa-sandbox.com").unwrap(),
                banxa_api_key: Default::default(),
                resend_api_key: Default::default(),
            },
            config.clone(),
            registry.clone(),
        )
        .await?;
    }

    Ok(())
}
