use crate::e2e::environment::Environment;
use relay::{cli::Args, spawn::try_spawn_with_args};
use std::{
    env::temp_dir,
    net::{IpAddr, Ipv4Addr, TcpListener},
    str::FromStr,
};
use url::Url;

/// Finds an available port by binding to "127.0.0.1:0".
fn get_available_port() -> std::io::Result<u16> {
    // Binding to port 0 tells the OS to assign an available port.
    let listener = TcpListener::bind("127.0.0.1:0")?;
    Ok(listener.local_addr()?.port())
}

#[tokio::test]
async fn respawn_cli() -> eyre::Result<()> {
    let env = Environment::setup_with_prep().await?;

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
                port: get_available_port().unwrap(),
                metrics_port: get_available_port().unwrap(),
                max_connections: Default::default(),
                entrypoint: Default::default(),
                delegation_proxy: env.delegation,
                account_registry: Default::default(),
                simulator: Default::default(),
                endpoints: vec![Url::from_str(&env._anvil.as_ref().unwrap().endpoint()).unwrap()],
                fee_recipient: Default::default(),
                quote_ttl: Default::default(),
                rate_ttl: Default::default(),
                fee_tokens: Default::default(),
                user_op_gas_buffer: Default::default(),
                tx_gas_buffer: Default::default(),
                database_url: Default::default(),
                max_pending_transactions: Default::default(),
                num_signers: Default::default(),
                signers_mnemonic: mnemonic.parse().unwrap(),
                sequencer_endpoints: Default::default(),
            },
            config.clone(),
            registry.clone(),
        )
        .await?;
    }

    Ok(())
}
