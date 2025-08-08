//! Porto CLI tool for creating and managing Porto accounts.
//!
//! # Examples
//!
//! Create a new Porto account:
//! ```sh
//! porto account new myaccount --rpc-url https://relay.ithaca.xyz
//! ```
//!
//! Send a transaction:
//! ```sh
//! porto send 0x742d35Cc6634C0532925a3b8D23C1FDDd3B6d0E4 0x \
//!     --account myaccount \
//!     --rpc-url https://relay.ithaca.xyz \
//!     --fee-token 0xA0b86991c431C1e6cDC5a5d5f7EC0c35A1F6A0Ac
//! ```

use alloy::{
    hex,
    primitives::{Address, Bytes, U256},
    signers::{Signer, local::PrivateKeySigner},
};
use alloy_chains::Chain;
use clap::{Parser, Subcommand};
use eyre::Result;
use jsonrpsee::http_client::HttpClientBuilder;
use relay::{
    rpc::RelayApiClient,
    signers::Eip712PayLoadSigner,
    types::{
        Call, KeyType, KeyWith712Signer,
        rpc::{
            CallStatusCode, GetAssetsParameters, Meta, PrepareCallsCapabilities,
            PrepareCallsParameters, PrepareUpgradeAccountParameters, PrepareUpgradeAccountResponse,
            RequiredAsset, SendPreparedCallsCapabilities, SendPreparedCallsParameters,
            UpgradeAccountCapabilities, UpgradeAccountParameters, UpgradeAccountSignatures,
        },
    },
};
use serde::{Deserialize, Serialize};
use std::{fs, path::PathBuf};

/// Main CLI structure for the Porto CLI tool.
#[derive(Parser)]
#[command(name = "porto")]
#[command(about = "Porto CLI - Interact with Porto accounts", long_about = None)]
struct Cli {
    /// The subcommand to execute.
    #[command(subcommand)]
    command: Commands,
}

/// Top-level commands available in the Porto CLI.
#[derive(Subcommand)]
enum Commands {
    /// Manage Porto accounts
    #[command(subcommand)]
    Account(AccountSubcommands),
    /// Get all token balances across chains
    Assets {
        /// The account address to query assets for
        address: Address,
        /// RPC URL of the relay server
        #[arg(long, short)]
        rpc_url: String,
    },
    /// Send transaction
    Send(SendCommand),
}

/// Command for sending transactions through Porto accounts.
#[derive(Parser)]
struct SendCommand {
    /// Name of the account to send from
    #[arg(long)]
    account: String,
    /// Destination address for the transaction
    to: Address,
    /// Transaction calldata as hex string
    data: Bytes,
    /// ETH value to send (optional, defaults to 0)
    #[arg(long, default_value = "0")]
    value: U256,
    /// RPC URL of the relay server
    #[arg(long, short)]
    rpc_url: String,
    /// Fee token address (optional)
    #[arg(long)]
    fee_token: Option<Address>,
    /// Required funds on the target chain (address:amount format)
    #[arg(long, value_name = "ADDRESS:AMOUNT")]
    required_funds: Vec<String>,
    /// Override the chain ID (optional, will query from RPC if not provided)
    #[arg(long)]
    chain: Chain,
}

impl SendCommand {
    /// Executes the send command, preparing and sending a transaction through the relay.
    async fn run(self) -> Result<()> {
        // Find the accoufnt by name
        let storage = AccountStorage::load()?;
        let account = storage.find_account_by_name(&self.account).ok_or_else(|| {
            eyre::eyre!(
                "Account '{}' not found. Run 'porto account ls' to see available accounts",
                self.account
            )
        })?;

        // Recreate the admin key from saved private key
        let admin_key_bytes = hex::decode(&account.admin_key_private)?;
        let admin_private_key = alloy::primitives::B256::from_slice(&admin_key_bytes);
        let admin_key =
            KeyWith712Signer::mock_admin_with_key(KeyType::Secp256k1, admin_private_key)?
                .expect("failed to recreate admin key");

        let client = HttpClientBuilder::default().build(&self.rpc_url)?;

        // Parse required funds
        let mut parsed_required_funds = Vec::new();
        for fund_str in self.required_funds {
            let parts: Vec<&str> = fund_str.split(':').collect();
            if parts.len() != 2 {
                return Err(eyre::eyre!(
                    "Invalid required_funds format '{}'. Expected 'ADDRESS:AMOUNT'",
                    fund_str
                ));
            }
            let address = parts[0].parse::<Address>()?;
            let amount = parts[1].parse::<U256>()?;
            parsed_required_funds.push(RequiredAsset::new(address, amount));
        }

        let chain_id = self.chain.id();

        // Prepare the call
        let call = Call { to: self.to, value: self.value, data: self.data };

        let meta = Meta {
            fee_payer: None,
            fee_token: self.fee_token.unwrap_or(Address::ZERO),
            nonce: None,
        };

        let capabilities = PrepareCallsCapabilities {
            authorize_keys: vec![],
            meta,
            revoke_keys: vec![],
            pre_calls: vec![],
            pre_call: false,
            required_funds: parsed_required_funds,
        };

        let params = PrepareCallsParameters {
            from: Some(account.address),
            chain_id,
            calls: vec![call],
            capabilities,
            state_overrides: Default::default(),
            balance_overrides: Default::default(),
            key: Some(admin_key.to_call_key()),
        };

        let prepare_response = client.prepare_calls(params).await?;
        println!("Prepared bundle with digest: {}", prepare_response.digest);

        // Sign the transaction with the admin key
        let signature = admin_key.sign_payload_hash(prepare_response.digest).await?;

        // Create the call key for Secp256k1
        // Use the key from prepare_calls response
        let call_key = prepare_response.key;

        // Send the prepared transaction
        let send_params = SendPreparedCallsParameters {
            capabilities: SendPreparedCallsCapabilities::default(),
            context: prepare_response.context,
            key: call_key.expect("key not found"),
            signature,
        };

        let send_response = client.send_prepared_calls(send_params).await?;
        println!("Sent bundle with ID: {}", send_response.id);

        // Wait for bundle confirmation
        let mut attempts = 0;
        let max_attempts = 30; // Wait up to 30 seconds

        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            attempts += 1;

            match client.get_calls_status(send_response.id).await {
                Ok(status) => {
                    match status.status {
                        CallStatusCode::Pending => {
                            if attempts % 5 == 0 {
                                println!("Still pending... ({}/{})", attempts, max_attempts);
                            }
                        }
                        CallStatusCode::Confirmed | CallStatusCode::PreConfirmed => {
                            if status.status == CallStatusCode::PreConfirmed {
                                println!("✅ Bundle pre-confirmed!");
                            } else {
                                println!("✅ Bundle confirmed!");
                            }
                            if !status.receipts.is_empty() {
                                for receipt in &status.receipts {
                                    println!(
                                        "  Chain {}: Transaction hash {}",
                                        receipt.chain_id, receipt.transaction_hash
                                    );
                                }
                            }
                            break;
                        }
                        CallStatusCode::Failed => {
                            println!("❌ Bundle failed!");
                            // Error details might be in receipts or other fields
                            break;
                        }
                        _ => {
                            println!("Bundle status: {:?}", status.status);
                        }
                    }
                }
                Err(e) => {
                    println!("Error checking status: {}", e);
                }
            }

            if attempts >= max_attempts {
                println!("⏰ Timeout waiting for confirmation after {} seconds", max_attempts);
                println!(
                    "You can check the status later with: porto tx status {} --rpc-url {}",
                    send_response.id, self.rpc_url
                );
                break;
            }
        }

        Ok(())
    }
}

/// Account management subcommands.
#[derive(Subcommand)]
enum AccountSubcommands {
    #[command(about = "Create a new Porto account")]
    New {
        /// Name for the new account
        name: String,
        /// RPC URL of the relay server
        #[arg(long, short)]
        rpc_url: String,
        /// The chain to create the account on.
        #[arg(long)]
        chain: Chain,
    },
    #[command(about = "List saved account addresses")]
    Ls,
}

impl AccountSubcommands {
    /// Executes the account management subcommand.
    async fn run(self) -> Result<()> {
        match self {
            AccountSubcommands::New { rpc_url, name, chain } => {
                println!("Creating new Porto account...");

                // Generate new keypair
                let signer = PrivateKeySigner::random();
                let address = signer.address();
                let private_key = hex::encode(signer.to_bytes());

                // Create admin key for the account using a deterministic private key
                let admin_private_key = alloy::primitives::B256::random();
                let admin_key =
                    KeyWith712Signer::mock_admin_with_key(KeyType::Secp256k1, admin_private_key)?
                        .expect("failed to create admin key");

                println!("Generated address: {}", address);

                // Create relay client
                let client = HttpClientBuilder::default().build(&rpc_url)?;
                let chain_id = chain.id();

                // Get relay capabilities to fetch delegation proxy address
                let capabilities = client.get_capabilities(vec![chain_id]).await?;
                let chain_capabilities = capabilities
                    .0
                    .get(&chain_id)
                    .ok_or_else(|| eyre::eyre!("Chain {} not supported by relay", chain_id))?;
                let delegation_address = chain_capabilities.contracts.delegation_proxy.address;

                // Prepare upgrade account
                let params = PrepareUpgradeAccountParameters {
                    address,
                    chain_id: Some(chain_id),
                    capabilities: UpgradeAccountCapabilities {
                        authorize_keys: vec![admin_key.to_authorized()],
                    },
                    delegation: delegation_address,
                };

                let PrepareUpgradeAccountResponse { context, digests, .. } =
                    client.prepare_upgrade_account(params).await?;

                // Sign the digests
                let auth_signature = signer.sign_hash(&digests.auth).await?;
                let exec_signature = signer.sign_hash(&digests.exec).await?;

                // Complete upgrade
                let upgrade_params = UpgradeAccountParameters {
                    signatures: UpgradeAccountSignatures {
                        auth: auth_signature,
                        exec: exec_signature,
                    },
                    context,
                };

                client.upgrade_account(upgrade_params).await?;
                println!("Account upgraded successfully!");

                // Save account with both EOA and admin keys
                let admin_key_hash = hex::encode(admin_key.key_hash().as_slice());
                let admin_private_hex = hex::encode(admin_private_key.as_slice());
                let mut storage = AccountStorage::load()?;

                // Check if name already exists
                if storage.find_account_by_name(&name).is_some() {
                    return Err(eyre::eyre!("Account with name '{}' already exists", name));
                }

                storage.add_account(
                    name.clone(),
                    address,
                    private_key,
                    admin_private_hex,
                    admin_key_hash,
                );
                storage.save()?;

                println!("Account '{}' saved locally", name);
            }
            AccountSubcommands::Ls => {
                let storage = AccountStorage::load()?;
                if storage.accounts.is_empty() {
                    println!("No saved accounts");
                } else {
                    println!("Saved accounts:");
                    for account in &storage.accounts {
                        println!("  {} ({})", account.name, account.address);
                    }
                }
            }
        }
        Ok(())
    }
}

/// Represents a saved Porto account with all necessary keys and metadata.
#[derive(Debug, Serialize, Deserialize)]
struct SavedAccount {
    /// Human-readable name for the account
    name: String,
    /// The account's Ethereum address
    address: Address,
    /// EOA private key used for initial delegation (hex-encoded)
    private_key: String,
    /// Admin key private key for transaction signing (hex-encoded)
    admin_key_private: String,
    /// Hex-encoded admin key hash for identification
    admin_key_hash: String,
}

/// Local storage container for saved Porto accounts.
///
/// Accounts are persisted to `~/.porto/accounts.json` as JSON.
#[derive(Debug, Serialize, Deserialize, Default)]
struct AccountStorage {
    /// List of saved accounts
    accounts: Vec<SavedAccount>,
}

impl AccountStorage {
    /// Loads account storage from disk, creating empty storage if file doesn't exist.
    fn load() -> Result<Self> {
        let path = Self::storage_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }

    /// Saves account storage to disk, creating parent directories if needed.
    fn save(&self) -> Result<()> {
        let path = Self::storage_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(self)?;
        fs::write(path, data)?;
        Ok(())
    }

    /// Returns the path to the account storage file (`~/.porto/accounts.json`).
    fn storage_path() -> Result<PathBuf> {
        let home = dirs::home_dir().ok_or_else(|| eyre::eyre!("Could not find home directory"))?;
        Ok(home.join(".porto").join("accounts.json"))
    }

    /// Adds a new account to the storage.
    fn add_account(
        &mut self,
        name: String,
        address: Address,
        private_key: String,
        admin_key_private: String,
        admin_key_hash: String,
    ) {
        self.accounts.push(SavedAccount {
            name,
            address,
            private_key,
            admin_key_private,
            admin_key_hash,
        });
    }

    /// Finds an account by name, returning a reference if found.
    fn find_account_by_name(&self, name: &str) -> Option<&SavedAccount> {
        self.accounts.iter().find(|a| a.name == name)
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Account(subcommand) => subcommand.run().await?,
        Commands::Assets { address, rpc_url } => handle_assets(address, rpc_url).await?,
        Commands::Send(send_cmd) => send_cmd.run().await?,
    }

    Ok(())
}

async fn handle_assets(address: Address, rpc_url: String) -> Result<()> {
    let client = HttpClientBuilder::default().build(&rpc_url)?;

    let params = GetAssetsParameters {
        account: address,
        asset_filter: Default::default(),
        asset_type_filter: Default::default(),
        chain_filter: Default::default(),
    };

    let response = client.get_assets(params).await?;

    println!("Assets for {}:", address);

    for (chain_id, assets) in response.0.iter() {
        println!("\nChain: {}", chain_id);

        for asset in assets {
            match &asset.address {
                relay::types::rpc::AddressOrNative::Native => {
                    println!("  Native: {} ETH", asset.balance);
                }
                relay::types::rpc::AddressOrNative::Address(addr) => {
                    if let Some(metadata) = &asset.metadata {
                        println!(
                            "  {}: {} {}",
                            metadata.symbol.as_deref().unwrap_or("Unknown"),
                            asset.balance,
                            metadata.symbol.as_deref().unwrap_or("")
                        );
                    } else {
                        println!("  {}: {}", addr, asset.balance);
                    }
                }
            }
        }
    }

    Ok(())
}
