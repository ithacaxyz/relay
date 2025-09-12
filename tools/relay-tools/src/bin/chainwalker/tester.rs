use super::{report::*, utils::find_eulerian_path_indices};
use alloy::primitives::{Address, ChainId, U256};
use eyre::{Result, eyre};
use jsonrpsee::http_client::HttpClient;
use relay::{
    rpc::{RelayApiClient, adjust_balance_for_decimals},
    signers::{DynSigner, Eip712PayLoadSigner},
    storage::BundleStatus,
    types::{
        AssetUid, Call, KeyWith712Signer, Quotes, Signed,
        rpc::{
            Asset7811, BundleId, CallStatusCode, GetAssetsParameters, GetKeysParameters, Meta,
            PrepareCallsCapabilities, PrepareCallsParameters, PrepareCallsResponse,
            PrepareUpgradeAccountParameters, PrepareUpgradeAccountResponse, RelayCapabilities,
            RequiredAsset, SendPreparedCallsParameters, UpgradeAccountCapabilities,
            UpgradeAccountParameters, UpgradeAccountSignatures,
        },
    },
};
use relay_tools::common::{
    format_chain, format_prepare_debug, format_units_safe, normalize_amount,
};
use std::{
    collections::{HashMap, HashSet},
    ops::Not,
    time::{Duration, Instant},
};
use tracing::{debug, error, info, warn};

/// Main interop tester implementation
#[derive(Debug)]
pub struct InteropTester {
    pub test_account: DynSigner,
    pub relay_client: HttpClient,
    pub only_uids: Option<Vec<String>>,
    pub only_chains: Option<Vec<ChainId>>,
    pub exclude_chains: Option<Vec<ChainId>>,
    pub transfer_percentage: u8,
    pub no_run: bool,
    pub skip_settlement_wait: bool,
    pub no_key: bool,
    pub account_key: KeyWith712Signer,
}

impl InteropTester {
    /// Get capabilities with caching to avoid repeated calls
    async fn get_capabilities(&self) -> Result<RelayCapabilities> {
        self.relay_client.get_capabilities(None).await.map_err(Into::into)
    }

    /// Get the funder address for a specific chain
    async fn get_funder_address(&self, chain_id: ChainId) -> Result<Address> {
        let capabilities = self.get_capabilities().await?;
        let Some(caps) = capabilities.0.get(&chain_id) else {
            return Err(eyre!("No capabilities for chain {}", chain_id));
        };
        Ok(caps.contracts.funder.address)
    }

    /// Get balance for a specific address, chain and token
    async fn get_balance(
        &self,
        address: Address,
        chain_id: ChainId,
        token: Address,
    ) -> Result<U256> {
        let assets = self.relay_client.get_assets(GetAssetsParameters::eoa(address)).await?;
        Ok(assets.balance_on_chain(chain_id, token.into()))
    }

    /// Runs the interop test suite.
    ///
    /// This method executes the full test flow:
    /// 1. Verifies the test account is fresh (unless force is true)
    /// 2. Discovers all interop token connections
    /// 3. Plans test sequences for each token
    /// 4. Checks funder liquidity
    /// 5. Executes transfers between all connected chains
    /// 6. Monitors settlements
    /// 7. Generates a comprehensive test report
    ///
    /// # Arguments
    /// * `force` - Continue even if the account has been used before
    ///
    /// # Returns
    /// A complete test report with transfer results and balance information
    pub async fn run(&mut self, force: bool) -> Result<TestReport> {
        info!("Starting interop test run");

        // Step 1: Verify account is fresh
        self.verify_fresh_account(force).await?;

        // Step 2: Get capabilities and build token map
        let capabilities = self.get_capabilities().await?;
        let token_connections = self.build_token_connections(&capabilities)?;

        if token_connections.is_empty() {
            return Err(eyre!("No interop tokens found matching criteria"));
        }

        // Step 3: Get initial balances
        let initial_balances = self.get_all_balances(&capabilities).await?;

        // Step 4: Plan test sequence for each token UID
        // Each token UID will have its own starting chain based on where it has the highest balance
        let test_plan = self.plan_test_sequence(&token_connections, &initial_balances)?;

        // Step 6: Check funder liquidity
        self.check_funder_liquidity(&capabilities, &test_plan).await?;

        // Step 7: Display test plan
        display_test_plan(&test_plan, self.transfer_percentage);

        if self.no_run {
            info!("Exiting due to --no-run flag");

            // Collect all chain/token pairs from the test plan
            let mut used_chains_and_tokens = HashSet::new();
            for conn in test_plan {
                used_chains_and_tokens.insert((conn.from_chain, conn.from_token_address));
                used_chains_and_tokens.insert((conn.to_chain, conn.to_token_address));
            }

            return Ok(TestReport {
                test_account: self.test_account.address(),
                connections_tested: vec![],
                balance_report: BalanceReport {
                    initial_balances: format_balance_map(
                        &initial_balances,
                        Some(&used_chains_and_tokens),
                    ),
                    final_balances: format_balance_map(
                        &initial_balances,
                        Some(&used_chains_and_tokens),
                    ),
                },
                summary: TestSummary {
                    total_connections_tested: 0,
                    successful_transfers: 0,
                    failed_transfers: 0,
                    skipped_transfers: 0,
                    success_rate: 0.0,
                    total_time_ms: 0,
                    average_time_ms: 0,
                },
            });
        }

        // Step 8: Execute transfers
        let results = self.execute_transfers(&test_plan).await;

        let final_balances = self.get_all_balances(&capabilities).await?;
        let report = self.generate_report(results, initial_balances, final_balances);

        report.save()?;
        display_summary(&report)?;

        Ok(report)
    }

    async fn verify_fresh_account(&self, force: bool) -> Result<()> {
        match self
            .relay_client
            .get_keys(GetKeysParameters { address: self.test_account.address(), chain_ids: vec![] })
            .await
        {
            Ok(keys) => {
                // Account is delegated and has keys
                if force {
                    warn!(
                        address = %self.test_account.address(),
                        keys_found = keys.len(),
                        "Account has been used before. Continuing due to --force flag."
                    );
                    warn!(
                        "Only use --force if testing the same account implementation (no upgrades)"
                    );
                } else {
                    error!(
                        address = %self.test_account.address(),
                        keys_found = keys.len(),
                        "Account has been used before. For accurate testing, please create a new account."
                    );
                    info!("Create a new account with: cast wallet new");
                    info!("Then fund it and pass its private key to this script");
                    info!(
                        "Alternatively, use --force to continue if testing the same account implementation"
                    );
                    return Err(eyre!(
                        "Account must be fresh for testing (use --force to override)"
                    ));
                }
            }
            Err(e) => {
                // Check if it's the expected EoaNotDelegated error
                if e.to_string().contains("eoa not delegated") {
                    info!("Account verified as fresh (not delegated)");
                } else {
                    // Some other error occurred
                    return Err(eyre!("Failed to check account status: {}", e));
                }
            }
        }

        Ok(())
    }

    fn build_token_connections(
        &self,
        capabilities: &RelayCapabilities,
    ) -> Result<Vec<InteropConnection>> {
        let mut connections = Vec::new();
        let mut token_map: HashMap<AssetUid, Vec<(ChainId, Address, u8)>> = HashMap::new();

        // Build map of tokens by UID
        for (chain_id, chain_caps) in &capabilities.0 {
            // Handle chain filtering
            if let Some(only) = &self.only_chains {
                if !only.contains(chain_id) {
                    continue;
                }
            } else if let Some(exclude) = &self.exclude_chains
                && exclude.contains(chain_id)
            {
                continue;
            }

            for token in &chain_caps.fees.tokens {
                // Skip tokens that don't have interop enabled
                if !token.asset.interop {
                    continue;
                }

                if let Some(only) = &self.only_uids
                    && !only.iter().any(|uid| uid == token.uid.as_str())
                {
                    continue;
                }

                let chain_info = (*chain_id, token.asset.address, token.asset.decimals);
                let entries = token_map.entry(token.uid.clone()).or_default();
                // Only add if this exact chain/address combination doesn't already exist
                if !entries.iter().any(|e| e.0 == chain_info.0 && e.1 == chain_info.1) {
                    entries.push(chain_info);
                }
            }
        }

        // Generate all bidirectional connections
        let num_tokens = token_map.len();
        for (uid, chains) in token_map {
            if chains.len() < 2 {
                info!(
                    token = %uid,
                    chains = chains.len(),
                    "Skipping token - found on {} chain(s) with interop enabled, need at least 2",
                    chains.len()
                );
                continue; // Skip tokens that don't connect multiple chains
            }

            for i in 0..chains.len() {
                for j in 0..chains.len() {
                    if i != j {
                        connections.push(InteropConnection {
                            from_chain: chains[i].0,
                            to_chain: chains[j].0,
                            token_uid: uid.clone(),
                            from_token_address: chains[i].1,
                            to_token_address: chains[j].1,
                            from_token_decimals: chains[i].2,
                            to_token_decimals: chains[j].2,
                        });
                    }
                }
            }
        }

        info!(
            tokens = num_tokens,
            connections = connections.len(),
            "Found interop tokens and connections"
        );

        Ok(connections)
    }

    async fn get_all_balances(
        &self,
        capabilities: &RelayCapabilities,
    ) -> Result<HashMap<ChainId, Vec<Asset7811>>> {
        let assets = self
            .relay_client
            .get_assets(GetAssetsParameters::eoa(self.test_account.address()))
            .await?;

        // Filter to only include chains that are in capabilities
        Ok(assets
            .0
            .into_iter()
            .filter(|(chain_id, _)| capabilities.0.contains_key(chain_id))
            .collect())
    }

    fn plan_test_sequence(
        &self,
        connections: &[InteropConnection],
        initial_balances: &HashMap<ChainId, Vec<Asset7811>>,
    ) -> Result<Vec<InteropConnection>> {
        // Group connections by token UID
        let mut by_token: HashMap<AssetUid, Vec<InteropConnection>> = HashMap::new();
        for conn in connections {
            by_token.entry(conn.token_uid.clone()).or_default().push(conn.clone());
        }

        // Create efficient path for each token
        let mut planned = Vec::new();
        for (uid, conns) in by_token {
            // Find the starting chain for this specific token (where it has the highest balance)
            // Use highest decimal precision for comparison
            let max_decimals = conns
                .iter()
                .map(|c| c.from_token_decimals.max(c.to_token_decimals))
                .max()
                .unwrap_or(18);

            let mut max_balance_normalized = U256::ZERO;
            let mut starting_chain = None;

            // Get all chains that have this token
            let token_chains: HashSet<ChainId> =
                conns.iter().flat_map(|c| vec![c.from_chain, c.to_chain]).collect();

            for chain_id in token_chains {
                if let Some(chain_assets) = initial_balances.get(&chain_id) {
                    // Find this token's balance on this chain
                    let token_data = chain_assets.iter().find_map(|a| {
                        conns.iter().find_map(|conn| {
                            if conn.from_chain == chain_id
                                && conn.from_token_address == a.address.address()
                            {
                                Some((a.balance, conn.from_token_decimals))
                            } else if conn.to_chain == chain_id
                                && conn.to_token_address == a.address.address()
                            {
                                Some((a.balance, conn.to_token_decimals))
                            } else {
                                None
                            }
                        })
                    });

                    if let Some((balance, decimals)) = token_data {
                        // Normalize to highest precision for fair comparison
                        let normalized_balance = normalize_amount(balance, decimals, max_decimals);

                        if normalized_balance > max_balance_normalized {
                            max_balance_normalized = normalized_balance;
                            starting_chain = Some(chain_id);
                        }
                    }
                }
            }

            let Some(start_chain) = starting_chain else {
                // No balance found on any chain for this token, skip it
                info!(
                    token = %uid,
                    "No balance found for token on any chain, skipping"
                );
                continue;
            };

            info!(
                token = %uid,
                connections = conns.len(),
                starting_chain = %format_chain(start_chain),
                balance = %format_units_safe(max_balance_normalized, max_decimals),
                "Planning test sequence for token"
            );

            // Extract unique chains
            let mut chains: Vec<ChainId> = conns
                .iter()
                .flat_map(|c| vec![c.from_chain, c.to_chain])
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            chains.sort(); // Sort to ensure consistent ordering

            // Find the index of the starting chain
            let start_idx = chains.iter().position(|&c| c == start_chain).unwrap_or(0);

            let n = chains.len();
            let mut path = Vec::new();

            // Debug logging
            info!(
                "Chain order: {:?}, start_chain: {}, start_idx: {}",
                chains.iter().map(|c| format_chain(*c)).collect::<Vec<_>>(),
                format_chain(start_chain),
                start_idx
            );

            let eulerian_path = find_eulerian_path_indices(n, start_idx);

            // Convert indices to actual connections
            for (from_idx, to_idx) in eulerian_path {
                let from_chain = chains[from_idx];
                let to_chain = chains[to_idx];

                // Find the connection in our conns vector
                if let Some(conn) =
                    conns.iter().find(|c| c.from_chain == from_chain && c.to_chain == to_chain)
                {
                    path.push(conn.clone());
                } else {
                    error!("Missing connection from {} to {}", from_chain, to_chain);
                }
            }

            // Verify we got all edges
            if path.len() != conns.len() {
                error!(
                    "Path construction failed for token {}. Expected {} edges, got {}",
                    uid,
                    conns.len(),
                    path.len()
                );
            }

            planned.extend(path);
        }

        Ok(planned)
    }

    async fn check_transfer_funder_liquidity(
        &self,
        conn: &InteropConnection,
        transfer_amount: U256,
    ) -> Result<()> {
        let funder_addr = self.get_funder_address(conn.to_chain).await?;
        let funder_balance =
            self.get_balance(funder_addr, conn.to_chain, conn.to_token_address).await?;

        // The destination funder needs to have enough to cover the transfer amount
        // (The relay will handle pulling from various source chains)
        if funder_balance
            < adjust_balance_for_decimals(
                transfer_amount,
                conn.from_token_decimals,
                conn.to_token_decimals,
            )
        {
            error!(
                chain = %format_chain(conn.to_chain),
                token = %conn.to_token_address,
                uid = %conn.token_uid,
                required = %format_units_safe(transfer_amount, conn.from_token_decimals),
                available = %format_units_safe(funder_balance, conn.to_token_decimals),
                "Destination chain funder has insufficient balance for this transfer"
            );
            return Err(eyre!(
                "Funder on {} has insufficient {} balance: {} required, {} available",
                format_chain(conn.to_chain),
                conn.token_uid,
                format_units_safe(transfer_amount, conn.from_token_decimals),
                format_units_safe(funder_balance, conn.to_token_decimals)
            ));
        }

        debug!(
            chain = %format_chain(conn.to_chain),
            token = %conn.to_token_address,
            uid = %conn.token_uid,
            required = %format_units_safe(transfer_amount, conn.from_token_decimals),
            available = %format_units_safe(funder_balance, conn.to_token_decimals),
            "Destination chain funder has sufficient balance for this transfer"
        );

        Ok(())
    }

    async fn check_funder_liquidity(
        &self,
        capabilities: &RelayCapabilities,
        test_plan: &[InteropConnection],
    ) -> Result<()> {
        info!("Checking funder balances...");

        // Get user's assets first to determine max balance per token
        let user_assets = self
            .relay_client
            .get_assets(GetAssetsParameters::eoa(self.test_account.address()))
            .await?;

        // For each token, find:
        // 1. The starting chain (where user has highest balance)
        // 2. Max balance the user has across all chains
        let mut token_info: HashMap<AssetUid, (ChainId, U256, u8)> = HashMap::new();

        for conn in test_plan {
            let uid = &conn.token_uid;

            let mut update_token_info = |chain: ChainId, token: Address, decimals: u8| {
                let balance = user_assets.balance_on_chain(chain, token.into());
                token_info
                    .entry(uid.clone())
                    .and_modify(|(start_chain, max_bal, start_decimals)| {
                        if adjust_balance_for_decimals(balance, decimals, *start_decimals)
                            > *max_bal
                        {
                            *max_bal = balance;
                            *start_chain = chain;
                            *start_decimals = decimals;
                        }
                    })
                    .or_insert((chain, balance, decimals));
            };

            update_token_info(conn.from_chain, conn.from_token_address, conn.from_token_decimals);
            update_token_info(conn.to_chain, conn.to_token_address, conn.to_token_decimals);
        }

        // Get funder balances for all chains
        let mut funder_balances: HashMap<(ChainId, Address), U256> = HashMap::new();
        for (chain_id, chain_caps) in &capabilities.0 {
            let funder_addr = chain_caps.contracts.funder.address;
            let assets =
                self.relay_client.get_assets(GetAssetsParameters::eoa(funder_addr)).await?;

            for asset in assets.0.get(chain_id).unwrap_or(&Vec::new()) {
                funder_balances.insert((*chain_id, asset.address.address()), asset.balance);
            }
        }

        // Smart check: funders need the max balance EXCEPT on the starting chain
        let mut insufficient = Vec::new();

        for conn in test_plan {
            let (starting_chain, max_balance, start_decimals) =
                token_info.get(&conn.token_uid).unwrap();

            // Helper to check funder balance
            let mut check_funder = |chain: ChainId, token: Address, decimals: u8| {
                if chain != *starting_chain {
                    let key = (chain, token);
                    let funder_balance = funder_balances.get(&key).copied().unwrap_or(U256::ZERO);
                    if adjust_balance_for_decimals(funder_balance, decimals, *start_decimals)
                        < *max_balance
                    {
                        insufficient.push((
                            key,
                            format_units_safe(*max_balance, *start_decimals),
                            format_units_safe(funder_balance, decimals),
                            conn.token_uid.clone(),
                        ));
                    }
                }
            };

            check_funder(conn.from_chain, conn.from_token_address, conn.from_token_decimals);
            check_funder(conn.to_chain, conn.to_token_address, conn.to_token_decimals);
        }

        // Deduplicate insufficient entries
        insufficient.sort_by_key(|k| k.0);
        insufficient.dedup_by_key(|k| k.0);

        if !insufficient.is_empty() {
            error!("Insufficient funder liquidity detected:");
            for ((chain_id, token), required, available, uid) in insufficient {
                error!(
                    chain = %format_chain(chain_id),
                    token = %token,
                    uid = %uid,
                    required = %required,
                    available = %available,
                    "Funder has insufficient balance"
                );
            }
            info!(
                "Note: Funders on the starting chain (where user has highest balance) are excluded from this check"
            );
            return Err(eyre!("One or more funders have insufficient liquidity"));
        }

        info!("All funders have sufficient liquidity");
        Ok(())
    }

    async fn execute_transfers(&mut self, test_plan: &[InteropConnection]) -> Vec<TransferResult> {
        let mut results = Vec::new();
        let mut current_token_uid = None;
        let mut skip_token: Option<AssetUid> = None;

        // Check if account is already delegated/initialized
        let mut account_initialized = self
            .relay_client
            .get_keys(GetKeysParameters { address: self.test_account.address(), chain_ids: vec![] })
            .await
            .is_ok();

        if account_initialized {
            info!("Account already delegated, skipping initialization");
        }

        for conn in test_plan {
            // Skip if we're skipping this token
            if let Some(ref skip_uid) = skip_token {
                if &conn.token_uid == skip_uid {
                    results.push(TransferResult {
                        from_chain_id: conn.from_chain,
                        to_chain_id: conn.to_chain,
                        token_uid: conn.token_uid.to_string(),
                        from_token_address: conn.from_token_address,
                        to_token_address: conn.to_token_address,
                        bundle_id: None,
                        required_funds: "0".to_string(),
                        required_funds_raw: U256::ZERO,
                        from_decimals: conn.from_token_decimals,
                        to_decimals: conn.to_token_decimals,
                        total_fee: U256::ZERO,
                        total_fee_formatted: "0".to_string(),
                        status: "Skipped".to_string(),
                        duration_ms: None,
                        error: Some("Skipped due to previous failure".to_string()),
                        failed_quotes: vec![],
                    });
                    continue;
                } else {
                    // Different token, clear skip flag
                    skip_token = None;
                }
            }

            // Check if we're starting a new token
            if current_token_uid.as_ref() != Some(&conn.token_uid) {
                current_token_uid = Some(conn.token_uid.clone());
                info!(
                    token = %conn.token_uid,
                    "Starting transfers for token"
                );
            }

            // Initialize account on first transfer only
            if !account_initialized {
                info!("Initializing account on first transfer");
                if let Err(e) = self.initialize_account(conn.from_chain).await {
                    error!(?e, "Failed to initialize account");
                    return vec![TransferResult {
                        from_chain_id: conn.from_chain,
                        to_chain_id: conn.to_chain,
                        token_uid: conn.token_uid.to_string(),
                        from_token_address: conn.from_token_address,
                        to_token_address: conn.to_token_address,
                        bundle_id: None,
                        required_funds: "0".to_string(),
                        required_funds_raw: U256::ZERO,
                        from_decimals: conn.from_token_decimals,
                        to_decimals: conn.to_token_decimals,
                        total_fee: U256::ZERO,
                        total_fee_formatted: "0".to_string(),
                        status: "Failed".to_string(),
                        duration_ms: None,
                        error: Some(format!("Account initialization failed: {e}")),
                        failed_quotes: vec![],
                    }];
                }
                account_initialized = true;
            }

            match self.execute_single_transfer(conn).await {
                Ok(result) => {
                    if result.status == "Failed" {
                        error!(
                            "Transfer failed, aborting remaining transfers for token {}",
                            conn.token_uid
                        );
                        results.push(result);
                        // Mark this token to be skipped
                        skip_token = Some(conn.token_uid.clone());
                    } else {
                        results.push(result);
                    }
                }
                Err(e) => {
                    error!(?e, "Transfer execution failed");
                    results.push(TransferResult {
                        from_chain_id: conn.from_chain,
                        to_chain_id: conn.to_chain,
                        token_uid: conn.token_uid.to_string(),
                        from_token_address: conn.from_token_address,
                        to_token_address: conn.to_token_address,
                        bundle_id: None,
                        required_funds: "0".to_string(),
                        required_funds_raw: U256::ZERO,
                        from_decimals: conn.from_token_decimals,
                        to_decimals: conn.to_token_decimals,
                        total_fee: U256::ZERO,
                        total_fee_formatted: "0".to_string(),
                        status: "Failed".to_string(),
                        duration_ms: None,
                        error: Some(e.to_string()),
                        failed_quotes: vec![],
                    });
                    // Mark this token to be skipped
                    skip_token = Some(conn.token_uid.clone());
                }
            }
        }

        results
    }

    async fn execute_single_transfer(&self, conn: &InteropConnection) -> Result<TransferResult> {
        let start_time = Instant::now();

        let from_chain = format_chain(conn.from_chain);
        let to_chain = format_chain(conn.to_chain);
        let token = conn.token_uid.as_str();

        info!(
            token = %token,
            from = %from_chain,
            to = %to_chain,
            "Starting transfer"
        );

        // Get all assets at once
        let all_assets = self
            .relay_client
            .get_assets(GetAssetsParameters::eoa(self.test_account.address()))
            .await?;

        // Extract balances for source and destination using the helper method
        let source_balance =
            all_assets.balance_on_chain(conn.from_chain, conn.from_token_address.into());
        let dest_balance = all_assets.balance_on_chain(conn.to_chain, conn.to_token_address.into());

        // Check if source has any balance
        if source_balance.is_zero() {
            warn!("Source chain has zero balance for token {}, skipping transfer", conn.token_uid);
            return failed_transfer_result(
                conn,
                U256::ZERO,
                "Skipped",
                "Zero balance on source chain".to_string(),
            );
        }

        // Calculate transfer amount with decimal normalization
        let transfer_from_source =
            source_balance * U256::from(self.transfer_percentage) / U256::from(100);

        // Log the calculation steps
        info!(
            source_balance_raw = %source_balance,
            transfer_percentage = self.transfer_percentage,
            transfer_from_source_raw = %transfer_from_source,
            "Calculated transfer amount from source"
        );

        let normalized_transfer_from_source = normalize_amount(
            transfer_from_source,
            conn.from_token_decimals,
            conn.to_token_decimals,
        );
        let total_transfer = normalized_transfer_from_source + dest_balance;

        info!(
            from_balance = %format_units_safe(source_balance, conn.from_token_decimals),
            from_balance_raw = %source_balance,
            from_decimals = conn.from_token_decimals,
            to_balance = %format_units_safe(dest_balance, conn.to_token_decimals),
            to_balance_raw = %dest_balance,
            to_decimals = conn.to_token_decimals,
            required_funds = %format_units_safe(total_transfer, conn.to_token_decimals),
            required_funds_raw = %total_transfer,
            transfer_percentage = self.transfer_percentage,
            "Preparing interop bundle..."
        );

        // Check if funders have sufficient balance for this specific transfer
        if let Err(e) = self.check_transfer_funder_liquidity(conn, transfer_from_source).await {
            error!("Funder liquidity check failed: {}", e);
            return failed_transfer_result(
                conn,
                total_transfer,
                "Failed",
                format!("Insufficient funder liquidity: {e}"),
            );
        }

        // Use the account key
        let key = &self.account_key;

        // Prepare the call - for interop, we receive tokens on the destination chain
        let call_transfer_amount = total_transfer / U256::from(2); // todo(joshie): there's an edge case on USDT that makes us understimate gas on a self transfer of the full amount.
        let call = if conn.to_token_address.is_zero() {
            // Native token transfer
            Call {
                to: self.test_account.address(),
                value: call_transfer_amount,
                data: Default::default(),
            }
        } else {
            // ERC20 transfer - transfer TO ourselves on destination chain
            Call::transfer(conn.to_token_address, self.test_account.address(), call_transfer_amount)
        };

        let prepare_params = PrepareCallsParameters {
            calls: vec![call],
            chain_id: conn.to_chain, // Execute on destination chain
            from: Some(self.test_account.address()),
            capabilities: PrepareCallsCapabilities {
                authorize_keys: vec![],
                revoke_keys: vec![],
                meta: Meta { fee_payer: None, fee_token: Some(conn.to_token_address), nonce: None },
                pre_calls: vec![],
                pre_call: false,
                // Required funds specifies what we need on destination chain
                required_funds: vec![RequiredAsset::new(conn.to_token_address, total_transfer)],
            },
            state_overrides: Default::default(),
            balance_overrides: Default::default(),
            key: self.no_key.not().then_some(key.to_call_key()),
        };

        let prepare_result = loop {
            match self.relay_client.prepare_calls(prepare_params.clone()).await {
                Ok(resp) => break Ok(resp),
                Err(e) if e.to_string().contains("exhausted max attempts") => {
                    // we get it from time to time but we should be good to go if we keep trying.
                    // don't stop walking
                    warn!("Retrying prepare_calls due to exhausted max attempts...");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Err(e) => break Err(e),
            }
        };

        let Ok(PrepareCallsResponse { context, digest, .. }) = prepare_result else {
            let e = prepare_result.unwrap_err();
            eprint!(
                "{}",
                format_prepare_debug(&prepare_params, None, Some("See error details above"))
            );
            error!(?e, "Failed to prepare calls");
            return failed_transfer_result(
                conn,
                total_transfer,
                "Failed",
                format!("Failed to prepare calls: {e}"),
            );
        };

        // Verify we have an interop bundle
        let Some(quotes) = context.quote() else {
            return Err(eyre!("No quotes returned"));
        };
        if quotes.ty().quotes.len() <= 1 {
            error!("Expected interop bundle but got {} quotes", quotes.ty().quotes.len());
            return failed_transfer_result(
                conn,
                total_transfer,
                "Failed",
                "No interop bundle created - check chain connectivity".to_string(),
            );
        }

        // Extract the quotes vector for storing in the result
        let quotes_vec = quotes.ty().quotes.clone();

        // Calculate total fee from all quotes
        let (total_fee, fee_formatted) = self.calculate_total_fee(quotes, conn)?;

        // Sign and send
        let signature = key.sign_payload_hash(digest).await?;

        let bundle_result = self
            .relay_client
            .send_prepared_calls(SendPreparedCallsParameters {
                capabilities: Default::default(),
                context,
                key: self.no_key.not().then_some(key.to_call_key()),
                signature,
            })
            .await;

        let Ok(resp) = bundle_result else {
            let e = bundle_result.unwrap_err();
            error!(?e, "Failed to send prepared calls");
            return failed_transfer_result_with_fee(
                conn,
                total_transfer,
                total_fee,
                fee_formatted.clone(),
                "Failed",
                format!("Failed to send calls: {e}"),
                quotes_vec.clone(),
            );
        };
        let bundle_id = resp.id;

        info!("📤 Bundle submitted: {}", bundle_id);

        // Monitor settlement
        let elapsed = start_time.elapsed();
        let settlement_result = self.monitor_settlement(bundle_id, conn).await;

        match settlement_result {
            Ok(_) => {
                let status_text = if self.skip_settlement_wait { "Confirmed" } else { "Settled" };

                // Get actual balances after the transfer
                let post_transfer_assets = self
                    .relay_client
                    .get_assets(GetAssetsParameters::eoa(self.test_account.address()))
                    .await?;

                let actual_from_balance = post_transfer_assets
                    .balance_on_chain(conn.from_chain, conn.from_token_address.into());
                let actual_to_balance = post_transfer_assets
                    .balance_on_chain(conn.to_chain, conn.to_token_address.into());

                info!(
                    token = %conn.token_uid.as_str(),
                    from_chain = %format_chain(conn.from_chain),
                    to_chain = %format_chain(conn.to_chain),
                    from_remaining = %format_units_safe(actual_from_balance, conn.from_token_decimals),
                    to_balance = %format_units_safe(actual_to_balance, conn.to_token_decimals),
                    status = %status_text,
                    duration_ms = elapsed.as_millis(),
                    "✅ Transfer complete"
                );

                Ok(create_transfer_result(
                    conn,
                    total_transfer,
                    total_fee,
                    fee_formatted.clone(),
                    Some(bundle_id),
                    status_text,
                    Some(elapsed.as_millis() as u64),
                    None,
                    vec![], // Success - no need to store quotes
                ))
            }
            Err(e) => {
                error!(
                    ?e,
                    duration_ms = elapsed.as_millis(),
                    "❌ Transfer failed during settlement"
                );

                Ok(create_transfer_result(
                    conn,
                    total_transfer,
                    total_fee,
                    fee_formatted,
                    Some(bundle_id),
                    "Failed",
                    Some(elapsed.as_millis() as u64),
                    Some(e.to_string()),
                    quotes_vec,
                ))
            }
        }
    }

    fn calculate_total_fee(
        &self,
        quotes: &Signed<Quotes>,
        conn: &InteropConnection,
    ) -> Result<(U256, String)> {
        // Find the token with the highest decimals among the fee tokens
        let mut max_decimals = 0u8;
        let mut total_fee_normalized = U256::ZERO;

        for quote in &quotes.ty().quotes {
            // Determine decimals for this quote's fee token
            let decimals = if quote.chain_id == conn.from_chain {
                conn.from_token_decimals
            } else if quote.chain_id == conn.to_chain {
                conn.to_token_decimals
            } else {
                // Default to 18 for other chains (shouldn't happen in 2-chain interop)
                18
            };

            if decimals > max_decimals {
                // Scale up the existing total to the new precision
                total_fee_normalized =
                    normalize_amount(total_fee_normalized, max_decimals, decimals);
                max_decimals = decimals;
            }

            // Normalize this fee to the max decimals and add
            let normalized_fee =
                normalize_amount(quote.intent.total_payment_amount(), decimals, max_decimals);
            total_fee_normalized += normalized_fee;
        }

        let fee_formatted = format_units_safe(total_fee_normalized, max_decimals);

        Ok((total_fee_normalized, fee_formatted))
    }

    async fn initialize_account(&mut self, chain_id: ChainId) -> Result<()> {
        info!("Preparing account upgrade on chain {}", format_chain(chain_id));

        // Get capabilities to find delegation proxy address
        let capabilities = self.get_capabilities().await?;
        let Some(chain_caps) = capabilities.0.get(&chain_id) else {
            return Err(eyre!("Chain {} not found in capabilities", chain_id));
        };

        // Use the existing account key
        let key = &self.account_key;

        // Prepare upgrade
        let PrepareUpgradeAccountResponse { context, digests, .. } = self
            .relay_client
            .prepare_upgrade_account(PrepareUpgradeAccountParameters {
                capabilities: UpgradeAccountCapabilities {
                    authorize_keys: vec![key.to_authorized()],
                },
                chain_id: Some(chain_id),
                address: self.test_account.address(),
                delegation: chain_caps.contracts.delegation_proxy.address,
            })
            .await
            .map_err(|e| eyre!("Failed to prepare account upgrade: {}", e))?;

        // Ensure this is nonce 0
        assert!(context.authorization.nonce == 0, "Authorization nonce should be 0.");

        // Sign the digests
        let auth_sig = self.test_account.sign_hash(&digests.auth).await?;
        let exec_sig = self.test_account.sign_hash(&digests.exec).await?;

        // Execute upgrade
        self.relay_client
            .upgrade_account(UpgradeAccountParameters {
                context,
                signatures: UpgradeAccountSignatures { auth: auth_sig, exec: exec_sig },
            })
            .await
            .map_err(|e| eyre!("Failed to upgrade account: {}", e))?;

        info!("Account initialized successfully on chain {}", format_chain(chain_id));

        Ok(())
    }

    async fn monitor_settlement(
        &self,
        bundle_id: BundleId,
        conn: &InteropConnection,
    ) -> Result<()> {
        let timeout = Duration::from_secs(300); // 5 minutes
        let start = Instant::now();

        loop {
            if start.elapsed() > timeout {
                return Err(eyre!(
                    "Settlement timeout exceeded for bundle {} ({} -> {})",
                    bundle_id,
                    format_chain(conn.from_chain),
                    format_chain(conn.to_chain)
                ));
            }

            let status = self.relay_client.get_calls_status(bundle_id).await?;

            // First check CallStatusCode
            match status.status {
                CallStatusCode::Confirmed => {
                    // Bundle confirmed, now check interop status if available and not skipping
                    if self.skip_settlement_wait {
                        // Skip waiting for interop settlement
                        info!(
                            "Bundle confirmed, skipping interop settlement wait (--skip-settlement-wait flag)"
                        );
                        return Ok(());
                    }

                    if let Some(interop_status) =
                        status.capabilities.as_ref().and_then(|c| c.interop_status)
                    {
                        match interop_status {
                            BundleStatus::Done => {
                                return Ok(());
                            }
                            BundleStatus::Failed => {
                                return Err(eyre!("Interop settlement failed"));
                            }
                            _ => {
                                // Still pending interop settlement
                                tokio::time::sleep(Duration::from_secs(2)).await;
                            }
                        }
                    } else {
                        // No interop status but confirmed - might be single chain
                        return Ok(());
                    }
                }
                CallStatusCode::Pending | CallStatusCode::PreConfirmed => {
                    // Still waiting for confirmation
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                CallStatusCode::Failed
                | CallStatusCode::Reverted
                | CallStatusCode::PartiallyReverted => {
                    return Err(eyre!("Bundle execution failed with status: {:?}", status.status));
                }
            }
        }
    }

    fn generate_report(
        &self,
        results: Vec<TransferResult>,
        initial_balances: HashMap<ChainId, Vec<Asset7811>>,
        final_balances: HashMap<ChainId, Vec<Asset7811>>,
    ) -> TestReport {
        let total_connections = results.len();
        let successful_transfers =
            results.iter().filter(|r| r.status == "Confirmed" || r.status == "Settled").count();
        let failed_transfers = results.iter().filter(|r| r.status == "Failed").count();
        let skipped_transfers = results.iter().filter(|r| r.status == "Skipped").count();
        let success_rate = if total_connections > 0 {
            successful_transfers as f64 / total_connections as f64
        } else {
            0.0
        };

        let total_duration: u64 = results.iter().filter_map(|r| r.duration_ms).sum();

        let settled_count = results.iter().filter(|r| r.duration_ms.is_some()).count();
        let average_duration =
            if settled_count > 0 { total_duration / settled_count as u64 } else { 0 };

        // Collect all chain/token pairs that were actually used in the test
        let mut used_chains_and_tokens = HashSet::new();
        for result in &results {
            used_chains_and_tokens.insert((result.from_chain_id, result.from_token_address));
            used_chains_and_tokens.insert((result.to_chain_id, result.to_token_address));
        }

        TestReport {
            test_account: self.test_account.address(),
            connections_tested: results,
            balance_report: BalanceReport {
                initial_balances: format_balance_map(
                    &initial_balances,
                    Some(&used_chains_and_tokens),
                ),
                final_balances: format_balance_map(&final_balances, Some(&used_chains_and_tokens)),
            },
            summary: TestSummary {
                total_connections_tested: total_connections,
                successful_transfers,
                failed_transfers,
                skipped_transfers,
                success_rate,
                total_time_ms: total_duration,
                average_time_ms: average_duration,
            },
        }
    }
}
