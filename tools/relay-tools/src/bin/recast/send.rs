//! Send subcommand for recast - sends tokens using the Ithaca relay

use alloy::primitives::{Address, ChainId, U256};
use clap::Parser;
use eyre::{Result, eyre};
use futures_util::try_join;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use relay::{
    rpc::RelayApiClient,
    signers::{DynSigner, Eip712PayLoadSigner},
    types::{
        Call, KeyWith712Signer,
        rpc::{
            AddressOrNative, BundleId, GetAssetsParameters, GetAssetsResponse, Meta,
            PrepareCallsCapabilities, PrepareCallsParameters, PrepareCallsResponse,
            RelayCapabilities, SendPreparedCallsParameters,
        },
    },
};
use relay_tools::common::{
    create_passkey, format_prepare_debug, format_units_safe, init_logging, parse_amount_to_wei,
    wait_for_calls_status,
};
use tracing::info;
use url::Url;

/// Send tokens using the Ithaca relay
#[derive(Debug, Parser)]
pub struct Args {
    /// Token UID (e.g., "tether", "teth")
    #[arg(long, value_name = "UID")]
    uid: String,

    /// Recipient address
    #[arg(long, value_name = "ADDRESS")]
    to: Address,

    /// Amount to send (in ether units, e.g., "1.5" for 1.5 ether)
    #[arg(long, value_name = "AMOUNT")]
    amount: String,

    /// Chain ID
    #[arg(long, value_name = "CHAIN_ID")]
    chain: ChainId,

    /// Fee token UID (defaults to the transfer token)
    #[arg(long, value_name = "UID")]
    fee_uid: Option<String>,

    /// Private key of the sender
    #[arg(long, value_name = "KEY", env = "PRIVATE_KEY")]
    private_key: String,

    /// Relay URL
    #[arg(long, default_value = "https://stg-rpc.ithaca.xyz")]
    relay_url: Url,

    /// Enable debug output
    #[arg(long)]
    debug: bool,
}

impl Args {
    /// Execute the send command
    pub async fn execute(self) -> Result<()> {
        init_logging();

        let relay_client = HttpClientBuilder::new().build(&self.relay_url)?;

        let eoa = DynSigner::from_signing_key(&self.private_key).await?;
        let account_key = create_passkey(&self.private_key)?;
        info!("Fetching capabilities and assets...");
        let (capabilities, user_assets) = try_join!(
            relay_client.get_capabilities(None), // Get all capabilities, we'll filter later
            relay_client.get_assets(GetAssetsParameters::eoa(eoa.address()))
        )?;

        let token = ResolvedToken::new(&capabilities, &self.uid, self.chain, &user_assets)?;

        let fee_token = if let Some(fee_uid) = &self.fee_uid {
            let fee_token_info =
                ResolvedToken::new(&capabilities, fee_uid, self.chain, &user_assets)?;
            fee_token_info.address
        } else {
            token.address
        };

        let amount = parse_amount_to_wei(&self.amount, token.decimals)?;

        info!(amount_wei = %amount, "Parsed amount");

        if amount > token.balance {
            return Err(eyre!(
                "Insufficient balance! Required: {} {}, Available: {} {}",
                self.amount,
                token.name.split(" (").next().unwrap_or(&token.name),
                format_units_safe(token.balance, token.decimals),
                token.name.split(" (").next().unwrap_or(&token.name)
            ));
        }

        info!(
            sender = %eoa.address(),
            recipient = %self.to,
            token = %token.name,
            amount = %self.amount,
            symbol = %token.symbol,
            chain_id = %self.chain,
            "Transaction details"
        );

        let prepare_response = self
            .prepare_transaction(
                &relay_client,
                vec![token.transfer(self.to, amount)],
                eoa.address(),
                fee_token,
                &account_key,
            )
            .await?;

        info!("Transaction prepared successfully");

        let bundle_id = send_transaction(&relay_client, prepare_response, &account_key).await?;
        info!("Waiting for transaction completion...");
        let status = wait_for_calls_status(&relay_client, bundle_id).await?;

        info!(status = ?status.status, "✅ Transaction completed");

        if !status.receipts.is_empty() {
            for receipt in &status.receipts {
                info!(
                    tx_hash = %receipt.transaction_hash,
                    block = ?receipt.block_number,
                    gas_used = %receipt.gas_used,
                    "Transaction receipt"
                );
            }
        }

        if !status.status.is_confirmed() {
            return Err(eyre!("❌ Transaction failed with status: {:?}", status.status));
        }

        Ok(())
    }

    /// Prepare the transaction
    async fn prepare_transaction(
        &self,
        relay_client: &HttpClient,
        calls: Vec<Call>,
        sender: Address,
        fee_token: Address,
        account_key: &KeyWith712Signer,
    ) -> Result<PrepareCallsResponse> {
        info!("Preparing transaction...");

        let prepare_params = PrepareCallsParameters {
            calls: calls.clone(),
            chain_id: self.chain,
            from: Some(sender),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: Some(fee_token), nonce: None },
                pre_calls: vec![],
                pre_call: false,
                required_funds: vec![],
            },
            state_overrides: Default::default(),
            balance_overrides: Default::default(),
            key: Some(account_key.to_call_key()),
        };

        if self.debug {
            print!("{}", format_prepare_debug(&prepare_params, None, None));
        }

        let response = relay_client.prepare_calls(prepare_params.clone()).await.map_err(|e| {
            // On error, always show debug info
            eprint!(
                "{}",
                format_prepare_debug(&prepare_params, None, Some("See error details above"))
            );
            eyre!("Failed to prepare calls: {}", e)
        })?;

        if self.debug {
            print!("{}", format_prepare_debug(&prepare_params, Some(&response), None));
        }

        Ok(response)
    }
}

/// Token information resolved from UID
struct ResolvedToken {
    pub address: Address,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub balance: U256,
    pub is_native: bool,
}

impl ResolvedToken {
    /// Create a ResolvedToken from capabilities and assets
    fn new(
        capabilities: &RelayCapabilities,
        uid: &str,
        chain_id: ChainId,
        assets: &GetAssetsResponse,
    ) -> Result<Self> {
        let chain_caps = capabilities
            .0
            .get(&chain_id)
            .ok_or_else(|| eyre!("No capabilities for chain {}", chain_id))?;

        let token_info =
            chain_caps.fees.tokens.iter().find(|t| t.uid.as_str() == uid).ok_or_else(|| {
                let available: Vec<String> = chain_caps
                    .fees
                    .tokens
                    .iter()
                    .map(|t| format!("{} ({})", t.uid, t.asset.address))
                    .collect();
                eyre!(
                    "Token UID '{}' not found on chain {}. Available: {}",
                    uid,
                    chain_id,
                    available.join(", ")
                )
            })?;

        let is_native = token_info.asset.address == Address::ZERO;
        let symbol = uid.to_string(); // Use UID as symbol

        let token_name = if is_native {
            format!("{} (native)", symbol)
        } else {
            format!("{} ({})", symbol, token_info.asset.address)
        };

        let balance = assets
            .0
            .get(&chain_id)
            .and_then(|chain_assets| {
                chain_assets
                    .iter()
                    .find(|asset| {
                        let asset_addr = match &asset.address {
                            AddressOrNative::Native => Address::ZERO,
                            AddressOrNative::Address(addr) => *addr,
                        };
                        asset_addr == token_info.asset.address
                    })
                    .map(|asset| asset.balance)
            })
            .ok_or_else(|| {
                eyre!("Token {} not found in user's assets on chain {}", uid, chain_id)
            })?;

        info!(
            balance = %format_units_safe(balance, token_info.asset.decimals),
            symbol = %symbol,
            "Current balance"
        );

        Ok(Self {
            address: token_info.asset.address,
            name: token_name,
            symbol,
            decimals: token_info.asset.decimals,
            balance,
            is_native,
        })
    }

    /// Create a transfer call
    fn transfer(&self, to: Address, amount: U256) -> Call {
        if self.is_native {
            Call { to, value: amount, data: Default::default() }
        } else {
            Call::transfer(self.address, to, amount)
        }
    }
}

/// Sign and send the prepared transaction
async fn send_transaction(
    relay_client: &HttpClient,
    prepare_response: PrepareCallsResponse,
    account_key: &KeyWith712Signer,
) -> Result<BundleId> {
    info!("Signing transaction...");

    let signature = account_key.sign_payload_hash(prepare_response.digest).await?;

    info!("Sending transaction...");
    let send_params = SendPreparedCallsParameters {
        capabilities: Default::default(),
        context: prepare_response.context,
        key: Some(account_key.to_call_key()),
        signature,
    };

    let send_response = relay_client
        .send_prepared_calls(send_params)
        .await
        .map_err(|e| eyre!("Failed to send transaction: {}", e))?;

    info!(bundle_id = %send_response.id, "✅ Transaction submitted successfully");

    Ok(send_response.id)
}
