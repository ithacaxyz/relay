use super::utils::{format_chain, format_units_safe};
use alloy::primitives::{Address, ChainId, U256};
use relay::types::{
    AssetUid, Quote,
    rpc::{Asset7811, BundleId},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    fs,
    time::{SystemTime, UNIX_EPOCH},
};
use tracing::info;

/// Result of a transfer attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferResult {
    pub from_chain_id: ChainId,
    pub to_chain_id: ChainId,
    pub token_uid: String,
    pub from_token_address: Address,
    pub to_token_address: Address,
    pub bundle_id: Option<BundleId>,
    pub required_funds: String,
    #[serde(serialize_with = "serialize_u256_as_decimal")]
    pub required_funds_raw: U256,
    pub from_decimals: u8,
    pub to_decimals: u8,
    #[serde(serialize_with = "serialize_u256_as_decimal")]
    pub total_fee: U256,
    pub total_fee_formatted: String,
    pub status: String,
    pub duration_ms: Option<u64>,
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub failed_quotes: Vec<Quote>,
}

/// Custom serializer for U256 to output as decimal string instead of hex
fn serialize_u256_as_decimal<S>(value: &U256, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serializer.serialize_str(&value.to_string())
}

/// Complete test report
#[derive(Debug, Serialize, Deserialize)]
pub struct TestReport {
    pub test_account: Address,
    pub connections_tested: Vec<TransferResult>,
    pub balance_report: BalanceReport,
    pub summary: TestSummary,
}

impl TestReport {
    /// Save report to JSON file with timestamp
    pub fn save(&self) -> eyre::Result<String> {
        let timestamp_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| eyre::eyre!("Failed to get system time: {}", e))?
            .as_millis();

        let filename = format!("report-{timestamp_ms}.json");
        let json = serde_json::to_string_pretty(&self)
            .map_err(|e| eyre::eyre!("Failed to serialize report: {}", e))?;

        fs::write(&filename, json)
            .map_err(|e| eyre::eyre!("Failed to write report to {}: {}", filename, e))?;

        info!(filename = %filename, "📋 Report saved");
        Ok(filename)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BalanceReport {
    pub initial_balances: HashMap<ChainId, HashMap<String, String>>,
    pub final_balances: HashMap<ChainId, HashMap<String, String>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TestSummary {
    pub total_connections_tested: usize,
    pub successful_transfers: usize,
    pub failed_transfers: usize,
    pub skipped_transfers: usize,
    pub success_rate: f64,
    pub total_time_ms: u64,
    pub average_time_ms: u64,
}

/// Format balance map for reporting
pub fn format_balance_map(
    balances: &HashMap<ChainId, Vec<Asset7811>>,
    used_chains_and_tokens: Option<&HashSet<(ChainId, Address)>>,
) -> HashMap<ChainId, HashMap<String, String>> {
    let mut formatted = HashMap::new();

    for (chain_id, assets) in balances {
        let mut chain_balances = HashMap::new();
        for asset in assets {
            // If we have a filter, only include assets that were used
            if let Some(used_set) = used_chains_and_tokens
                && !used_set.contains(&(*chain_id, asset.address.address()))
            {
                continue;
            }

            // Get decimals from metadata if available, default to 18
            let decimals = asset.metadata.as_ref().and_then(|m| m.decimals).unwrap_or(18);

            let formatted_balance = format_units_safe(asset.balance, decimals);
            let symbol = format!("0x{:x}", asset.address.address());
            chain_balances.insert(symbol, formatted_balance);
        }

        // Only include the chain if it has any tracked assets
        if !chain_balances.is_empty() {
            formatted.insert(*chain_id, chain_balances);
        }
    }

    formatted
}

/// Display the test summary and save report to file
pub fn display_summary(report: &TestReport) -> eyre::Result<()> {
    info!(
        total = report.summary.total_connections_tested,
        successful = report.summary.successful_transfers,
        failed = report.summary.failed_transfers,
        skipped = report.summary.skipped_transfers,
        success_rate = format!("{:.1}%", report.summary.success_rate * 100.0),
        total_time_ms = report.summary.total_time_ms,
        "Test summary"
    );

    // Group results by token
    let mut by_token: HashMap<String, Vec<&TransferResult>> = HashMap::new();
    for result in &report.connections_tested {
        by_token.entry(result.token_uid.clone()).or_default().push(result);
    }

    for (uid, results) in by_token {
        println!("\n🪙 Token: {uid}");
        for result in results {
            let status_icon = match result.status.as_str() {
                "Confirmed" | "Settled" => "✅",
                "Failed" => "❌",
                "Skipped" => "⏭️",
                "Submitted" => "📤",
                _ => "❓",
            };

            let details = if result.status == "Done" || result.status == "Submitted" {
                format!("({}, {}ms)", result.required_funds, result.duration_ms.unwrap_or(0))
            } else if let Some(error) = &result.error {
                format!("({error})")
            } else {
                "".to_string()
            };

            println!(
                "├─ {} {} → {} {}",
                status_icon,
                format_chain(result.from_chain_id),
                format_chain(result.to_chain_id),
                details
            );
        }
    }

    Ok(())
}

/// Represents a connection between two chains via a shared token
#[derive(Debug, Clone)]
pub struct InteropConnection {
    pub from_chain: ChainId,
    pub to_chain: ChainId,
    pub token_uid: AssetUid,
    pub from_token_address: Address,
    pub to_token_address: Address,
    pub from_token_decimals: u8,
    pub to_token_decimals: u8,
}

/// Display the test plan
pub fn display_test_plan(test_plan: &[InteropConnection], transfer_percentage: u8) {
    println!(
        "\nTransfers {}% of balance on each hop, retaining {}% for gas costs.",
        transfer_percentage,
        100 - transfer_percentage
    );
    println!();

    // Group by token for display
    let mut by_token: HashMap<AssetUid, Vec<&InteropConnection>> = HashMap::new();
    for conn in test_plan {
        by_token.entry(conn.token_uid.clone()).or_default().push(conn);
    }

    for (uid, conns) in by_token {
        // Count unique chains for this token
        let unique_chains: HashSet<ChainId> =
            conns.iter().flat_map(|c| vec![c.from_chain, c.to_chain]).collect();

        println!(
            "🪙 Token: {} ({} transfers) ({} chains)",
            uid.as_str(),
            conns.len(),
            unique_chains.len()
        );
        println!("─────────────────────────────────────────────────────────────────");
        for (i, conn) in conns.iter().enumerate() {
            println!(
                "  {}. {} → {}",
                i + 1,
                format_chain(conn.from_chain),
                format_chain(conn.to_chain)
            );
        }
        println!();
    }
}

/// Create a TransferResult with common fields
#[allow(clippy::too_many_arguments)]
pub fn create_transfer_result(
    conn: &InteropConnection,
    required_funds: U256,
    total_fee: U256,
    total_fee_formatted: String,
    bundle_id: Option<BundleId>,
    status: &str,
    duration_ms: Option<u64>,
    error: Option<String>,
    quotes: Vec<Quote>,
) -> TransferResult {
    TransferResult {
        from_chain_id: conn.from_chain,
        to_chain_id: conn.to_chain,
        token_uid: conn.token_uid.to_string(),
        from_token_address: conn.from_token_address,
        to_token_address: conn.to_token_address,
        bundle_id,
        required_funds: format_units_safe(required_funds, conn.to_token_decimals),
        required_funds_raw: required_funds,
        from_decimals: conn.from_token_decimals,
        to_decimals: conn.to_token_decimals,
        total_fee,
        total_fee_formatted,
        status: status.to_string(),
        duration_ms,
        error,
        failed_quotes: quotes,
    }
}

/// Create a failed TransferResult with standard fields
pub fn failed_transfer_result(
    conn: &InteropConnection,
    required_funds: U256,
    status: &str,
    error: String,
) -> eyre::Result<TransferResult> {
    Ok(create_transfer_result(
        conn,
        required_funds,
        U256::ZERO,
        "0".to_string(),
        None,
        status,
        None,
        Some(error),
        vec![],
    ))
}

/// Create a failed TransferResult with fee information and quotes
pub fn failed_transfer_result_with_fee(
    conn: &InteropConnection,
    required_funds: U256,
    total_fee: U256,
    total_fee_formatted: String,
    status: &str,
    error: String,
    quotes: Vec<Quote>,
) -> eyre::Result<TransferResult> {
    Ok(create_transfer_result(
        conn,
        required_funds,
        total_fee,
        total_fee_formatted,
        None,
        status,
        None,
        Some(error),
        quotes,
    ))
}
