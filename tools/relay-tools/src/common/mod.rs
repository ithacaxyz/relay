pub mod format;
pub mod signatures;

use alloy::{
    hex,
    primitives::{B256, U256, utils::parse_units},
};
use eyre::{Result, eyre};
use jsonrpsee::http_client::HttpClient;
use relay::{
    rpc::RelayApiClient,
    types::{
        KeyType, KeyWith712Signer,
        rpc::{BundleId, CallsStatus},
    },
};
use tokio::time::{Duration, sleep};
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

// Re-export commonly used items
pub use format::{format_chain, format_prepare_debug, format_units_safe};
pub use signatures::{SIGNATURES, Signatures};

/// Initialize logging - matches chainwalker/stress pattern
pub fn init_logging() {
    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(
            EnvFilter::builder().with_default_directive(LevelFilter::INFO.into()).from_env_lossy(),
        )
        .init();
}

/// Normalize an amount from one decimal precision to another - from chainwalker
pub fn normalize_amount(amount: U256, from_decimals: u8, to_decimals: u8) -> U256 {
    if from_decimals == to_decimals {
        amount
    } else if from_decimals > to_decimals {
        // Source has more decimals, divide to reduce precision
        let diff = from_decimals - to_decimals;
        amount / U256::from(10).pow(U256::from(diff))
    } else {
        // Source has fewer decimals, multiply to increase precision
        let diff = to_decimals - from_decimals;
        amount * U256::from(10).pow(U256::from(diff))
    }
}

/// Parse amount string to wei - from stress
pub fn parse_amount_to_wei(amount: &str, decimals: u8) -> Result<U256> {
    let u = parse_units(amount, decimals).map_err(|e| eyre!("Failed to parse amount: {}", e))?;
    U256::try_from(u).map_err(|e| eyre!("Amount too large: {}", e))
}

/// Create a passkey for signing - from stress
pub fn create_passkey(private_key_str: &str) -> Result<KeyWith712Signer> {
    let array = hex::decode_to_array::<_, 32>(private_key_str)
        .map_err(|e| eyre!("Invalid private key format: {}", e))?;
    let mock_key = B256::from(array);
    KeyWith712Signer::mock_admin_with_key(KeyType::Secp256k1, mock_key)?
        .ok_or_else(|| eyre!("Failed to create account key"))
}

/// Wait for transaction completion - from stress
pub async fn wait_for_calls_status(
    relay_client: &HttpClient,
    bundle_id: BundleId,
) -> Result<CallsStatus> {
    let status = loop {
        let status = relay_client.get_calls_status(bundle_id).await;
        if status
            .as_ref()
            .is_ok_and(|status| status.status.is_final() && !status.status.is_preconfirmed())
        {
            break status?;
        }
        sleep(Duration::from_millis(100)).await;
    };

    Ok(status)
}
