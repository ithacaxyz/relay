use super::signatures::Signatures;
use alloy::{
    hex,
    primitives::{ChainId, U256},
    sol_types::SolValue,
};
use relay::types::{
    Call, DiffDirection,
    rpc::{PrepareCallsContext, PrepareCallsParameters, PrepareCallsResponse},
};

/// Unified debug formatting for prepare_calls requests and responses
pub fn format_prepare_debug(
    params: &PrepareCallsParameters,
    response: Option<&PrepareCallsResponse>,
    error: Option<&str>,
) -> String {
    let signatures = Signatures::instance();
    let mut output = String::new();

    // Header based on context
    if error.is_some() {
        output.push_str("\n❌ ERROR: prepare_calls failed\n");
    } else if response.is_some() {
        output.push_str("\n🔍 DEBUG: prepare_calls response\n");
    } else {
        output.push_str("\n🔍 DEBUG: prepare_calls request\n");
    }
    output.push_str("================================\n");

    // Always show request details
    output.push_str(&format!("Chain ID: {}\n", params.chain_id));
    if let Some(from) = params.from {
        output.push_str(&format!("From: {}\n", from));
    }
    output.push_str(&format!("Fee token: {}\n", params.capabilities.meta.fee_token));
    if let Some(ref key) = params.key {
        output.push_str(&format!("Key: {:?}\n", key));
    }

    output.push_str(&format!("\nCalls ({}):\n", params.calls.len()));
    for (i, call) in params.calls.iter().enumerate() {
        output.push_str(&format!("  Call {}:\n", i));
        output.push_str(&format!("    To: {}\n", call.to));
        output.push_str(&format!("    Value: {} wei\n", call.value));
        output.push_str(&format!("    Function: {}\n", signatures.decode_call(call)));
    }

    // Show error if provided
    if let Some(err_msg) = error {
        output.push_str(&format!("\nError: {}\n", err_msg));
    }

    // Show response details if provided
    if let Some(response) = response {
        output.push_str(&format!("\nDigest: 0x{}\n", hex::encode(response.digest)));

        match &response.context {
            PrepareCallsContext::Quote(signed_quotes) => {
                output.push_str("\nContext type: Quote\n");
                let quotes = signed_quotes.ty();

                if !quotes.quotes.is_empty() {
                    output.push_str(&format!("\nQuotes ({}):\n", quotes.quotes.len()));
                    for (i, quote) in quotes.quotes.iter().enumerate() {
                        output.push_str(&format!("  Quote {}:\n", i));
                        output.push_str(&format!("    Chain ID: {}\n", quote.chain_id));

                        let execution_data = quote.intent.execution_data();
                        if !execution_data.is_empty() {
                            if let Ok(calls) = Vec::<Call>::abi_decode(&execution_data) {
                                output.push_str(&format!(
                                    "    Intent execution calls ({}):\n",
                                    calls.len()
                                ));
                                for (j, call) in calls.iter().enumerate() {
                                    output.push_str(&format!(
                                        "      Call {}: to={} value={} fn={}\n",
                                        j,
                                        call.to,
                                        call.value,
                                        signatures.decode_call(call)
                                    ));
                                }
                            } else {
                                output.push_str(&format!(
                                    "    Intent execution: 0x{}\n",
                                    hex::encode(&execution_data)
                                ));
                            }
                        }

                        output
                            .push_str(&format!("    Extra payment: {} wei\n", quote.extra_payment));
                    }
                }

                if let Some(root) = &quotes.multi_chain_root {
                    output.push_str(&format!("\nMulti-chain root: 0x{}\n", hex::encode(root)));
                }

                output.push_str(&format!(
                    "\nSigned quotes hash: 0x{}\n",
                    hex::encode(signed_quotes.hash())
                ));
            }
            PrepareCallsContext::PreCall(pre_call) => {
                output.push_str("\nContext type: PreCall\n");
                output.push_str(&format!("Pre-call data: {:?}\n", pre_call));
            }
        }

        // Asset diffs
        if !response.capabilities.asset_diff.asset_diffs.is_empty() {
            output.push_str("\nAsset diffs:\n");
            for (chain_id, asset_diffs) in &response.capabilities.asset_diff.asset_diffs {
                output.push_str(&format!("  Chain ID {}: \n", chain_id));
                for (address, diffs) in &asset_diffs.0 {
                    if !diffs.is_empty() {
                        output.push_str(&format!("    Account: {}\n", address));
                        for diff in diffs {
                            let asset_str = if let Some(addr) = diff.address {
                                format!("{}", addr)
                            } else {
                                "ETH (native)".to_string()
                            };

                            let value_str = match diff.direction {
                                DiffDirection::Incoming => {
                                    format!("+{}", diff.value)
                                }
                                DiffDirection::Outgoing => {
                                    format!("-{}", diff.value)
                                }
                            };

                            let metadata_str = if let Some(symbol) = &diff.metadata.symbol {
                                format!(" {}", symbol)
                            } else {
                                String::new()
                            };

                            output.push_str(&format!(
                                "      {} {}{}\n",
                                asset_str, value_str, metadata_str
                            ));
                        }
                    }
                }
            }
        }

        // Fee totals
        if !response.capabilities.asset_diff.fee_totals.is_empty() {
            output.push_str("\nApproximate fee totals:\n");
            for (chain_id, fee) in &response.capabilities.asset_diff.fee_totals {
                // Include all chains, not skipping chain_id 0
                output.push_str(&format!("  Chain {}: {} {}\n", chain_id, fee.value, fee.currency));
            }
        }
    }

    output.push_str("================================\n");
    output
}

/// Format a chain ID with its name if known
pub fn format_chain(chain_id: ChainId) -> String {
    let chain = alloy_chains::Chain::from(chain_id);
    let Some(named) = chain.named() else {
        return format!("{{{chain_id}}}");
    };
    format!("{{ {named}|{chain_id} }}")
}

/// Format units with proper error handling
pub fn format_units_safe(value: U256, decimals: u8) -> String {
    use alloy::primitives::utils::format_units;
    format_units(value, decimals).unwrap_or_else(|_| value.to_string())
}
