//! ERC20 balance storage slot discovery and caching.

use crate::{
    error::RelayError,
    types::{Assets, IERC20::balanceOfCall},
};
use alloy::{
    contract::StorageSlotFinder,
    primitives::{Address, B256, U256, keccak256},
    providers::{Provider, ext::DebugApi},
    rpc::types::{
        BlockId, TransactionRequest,
        state::{AccountOverride, StateOverridesBuilder},
        trace::geth::{GethDebugTracingCallOptions, GethDebugTracingOptions, GethTrace},
    },
    sol_types::SolCall,
};
use dashmap::DashMap;
use futures::future::join_all;
use std::sync::Arc;
use tracing::{debug, warn};

/// ERC20 balance storage slot tracker for a chain.
#[derive(Debug, Clone)]
pub struct Erc20Slots {
    /// Storage layout for each token address.
    layouts: Arc<DashMap<Address, BalanceLayout>>,
    /// Cache for unknown layout slots: (token, account) -> slot
    account_slots: Arc<DashMap<(Address, Address), B256>>,
}

impl Erc20Slots {
    /// Initialize the tracker by discovering mappings for all assets.
    pub async fn new<P: Provider + DebugApi>(
        provider: P,
        assets: &Assets,
    ) -> Result<Self, RelayError> {
        let instance =
            Self { layouts: Arc::new(DashMap::new()), account_slots: Arc::new(DashMap::new()) };

        // This will populate the cache with discovered layouts
        let test_account = Address::random();
        join_all(
            assets.iter().filter(|(_, desc)| desc.address != Address::ZERO).map(|(_, desc)| {
                instance.compute_balance_slot(&provider, desc.address, test_account)
            }),
        )
        .await;

        Ok(instance)
    }

    /// Get the storage slot for an ERC20 balance.
    ///
    /// 1. If layout cached:
    ///    - Standard or Solady → compute slot
    ///    - Unknown → check account_slots cache or use StorageSlotFinder (and cache it).
    /// 2. If layout not cached:
    ///    - Attempt to discover layout via opcode trace
    ///    - Go to 1.
    pub async fn compute_balance_slot<P: Provider + DebugApi>(
        &self,
        provider: &P,
        token: Address,
        account: Address,
    ) -> Result<Option<B256>, RelayError> {
        // Check if we have a cached layout
        if let Some(layout) = self.layouts.get(&token) {
            if let Some(slot) = layout.compute_slot(account) {
                return Ok(Some(slot));
            }
            // Unknown layout - check cache or discover slot
            if let Some(slot) = self.account_slots.get(&(token, account)) {
                return Ok(Some(*slot));
            }
            return self.discover_unknown_slot(provider, token, account).await;
        }

        debug!(token = %token, "Discovering layout for new token");
        self.discover_layout_and_compute_slot(provider, token, account).await
    }

    /// Discover layout for a token and compute the slot for an account.
    async fn discover_layout_and_compute_slot<P: Provider + DebugApi>(
        &self,
        provider: &P,
        token: Address,
        account: Address,
    ) -> Result<Option<B256>, RelayError> {
        let layout = BalanceLayout::discover(provider, token).await?;

        self.layouts.insert(token, layout.clone());

        // Now find the slot
        if let Some(slot) = layout.compute_slot(account) {
            Ok(Some(slot))
        } else {
            self.discover_unknown_slot(provider, token, account).await
        }
    }

    /// Discover a slot for an unknown layout using StorageSlotFinder and caches it.
    async fn discover_unknown_slot<P: Provider>(
        &self,
        provider: &P,
        token: Address,
        account: Address,
    ) -> Result<Option<B256>, RelayError> {
        let Some(slot) = StorageSlotFinder::balance_of(provider, token, account)
            // There's an issue with the `eth_createAccesslist` endpoint on at least polygon and BSC
            // where a regular request fails with
            //
            // > failed to apply transaction:
            // > 0x87321d84b5a1d6d4edfa02c729ba5784c8ea88a4fd3a0bb7de4441054c9c61c3 err:
            // > insufficient funds for gas * price + value: address
            // > 0x0000000000000000000000000000000000000000 have 99214501874407965562016 want
            // > 922337203685477580700000000
            //
            // A workaround for this is setting the gas limit field, a `balanceOf` call usually
            // consumes ~31k gas, so 100k should always be sufficient
            .with_request(TransactionRequest::default().gas_limit(100_000))
            .find_slot()
            .await?
        else {
            return Ok(None);
        };

        self.account_slots.insert((token, account), slot);
        Ok(Some(slot))
    }

    /// Check if we have a mapping calculation for a token.
    pub fn has_token(&self, token: Address) -> bool {
        self.layouts.contains_key(&token)
    }

    /// Check if a token has an unknown layout.
    pub fn is_unknown(&self, token: Address) -> bool {
        self.layouts.get(&token).is_none_or(|layout| matches!(*layout, BalanceLayout::Unknown))
    }
}

/// Storage layout schemes for ERC20 balance mappings.
#[derive(Debug, Clone)]
enum BalanceLayout {
    /// Known layout: keccak256(prefix || address || suffix)
    Known { prefix: Vec<u8>, suffix: Vec<u8> },
    /// Unknown layout - must use StorageSlotFinder for each account
    Unknown,
}

impl BalanceLayout {
    /// Discover the storage layout for an ERC20 token using opcode trace analysis.
    async fn discover<P: Provider + DebugApi>(
        provider: &P,
        token_address: Address,
    ) -> Result<Self, RelayError> {
        let eoa = Address::random();
        let tx = TransactionRequest::default()
            .to(token_address)
            .input(balanceOfCall { eoa }.abi_encode().into())
            .gas_limit(100_000);

        let trace_options = GethDebugTracingCallOptions {
            tracing_options: GethDebugTracingOptions {
                config: alloy::rpc::types::trace::geth::GethDefaultTracingOptions {
                    enable_memory: Some(true),
                    disable_stack: Some(false),
                    disable_storage: Some(false),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };

        debug!(token = %token_address, "Tracing balanceOf call");
        if let GethTrace::Default(frame) =
            provider.debug_trace_call(tx.clone(), BlockId::latest(), trace_options).await?
        {
            let mut found_keccak: Option<(B256, Vec<u8>)> = None;
            let struct_logs = frame.struct_logs;

            for (i, log) in struct_logs.iter().enumerate() {
                match log.op.as_ref() {
                    "KECCAK256" => {
                        if let Some(stack) = &log.stack
                            && let Some(memory) = &log.memory
                            && stack.len() >= 2
                        {
                            let offset = stack[stack.len() - 1].to::<usize>();
                            let length = stack[stack.len() - 2].to::<usize>();

                            // Convert memory from hex strings to bytes
                            let mut mem_bytes = Vec::new();
                            for word in memory {
                                if let Ok(bytes) = alloy::hex::decode(word) {
                                    mem_bytes.extend_from_slice(&bytes);
                                }
                            }

                            if offset + length <= mem_bytes.len() {
                                let input = &mem_bytes[offset..offset + length];

                                // Check if this keccak256 is for our test address
                                let matches_eoa = if input.len() == 64 {
                                    // Standard layout: check address in first 32 bytes
                                    let found_address = Address::from_slice(&input[12..32]);
                                    found_address == eoa
                                } else if input.len() == 32 {
                                    // Solady layout: check address in first 20 bytes
                                    let found_address = Address::from_slice(&input[0..20]);
                                    found_address == eoa
                                } else {
                                    false
                                };

                                if matches_eoa
                                    && i + 1 < struct_logs.len()
                                    && let Some(next_stack) = &struct_logs[i + 1].stack
                                    && !next_stack.is_empty()
                                {
                                    found_keccak = Some((
                                        B256::from(next_stack[next_stack.len() - 1]),
                                        input.to_vec(),
                                    ));
                                }
                            }
                        }
                    }
                    "SLOAD" => {
                        if let Some((hash_result, ref input)) = found_keccak
                            && let Some(stack) = &log.stack
                            && !stack.is_empty()
                        {
                            let slot_loaded = B256::from(stack[stack.len() - 1]);

                            if hash_result == slot_loaded {
                                // Find where the address appears in the input
                                let address_bytes = eoa.as_slice();

                                if let Some(pos) =
                                    input.windows(20).position(|w| w == address_bytes)
                                {
                                    let prefix = input[..pos].to_vec();
                                    let suffix = input[pos + 20..].to_vec();

                                    debug!(
                                        token = %token_address,
                                        prefix = %alloy::hex::encode(&prefix),
                                        suffix = %alloy::hex::encode(&suffix),
                                        "Found mapping layout via opcode trace"
                                    );

                                    return Self::Known { prefix, suffix }
                                        .ensure(provider, token_address)
                                        .await;
                                }
                            }
                        }
                    }
                    _ => {} // Ignore other opcodes
                }
            }
        }

        debug!(token = %token_address, "Could not find mapping offset in opcode trace");
        Ok(Self::Unknown)
    }

    /// Compute the storage slot for a given account address.
    /// For unknown layouts, returns None.
    fn compute_slot(&self, account: Address) -> Option<B256> {
        match self {
            BalanceLayout::Known { prefix, suffix } => {
                let mut data = Vec::with_capacity(prefix.len() + 20 + suffix.len());
                data.extend_from_slice(prefix);
                data.extend_from_slice(account.as_slice());
                data.extend_from_slice(suffix);
                Some(keccak256(&data))
            }
            BalanceLayout::Unknown => None,
        }
    }

    /// Ensures a discovered layout is legitimate by setting a test balance and checking it.
    ///
    /// Returns the layout if it succeeds, BalanceLayout::Unknown otherwise.
    async fn ensure<P: Provider>(
        self,
        provider: &P,
        token_address: Address,
    ) -> Result<BalanceLayout, RelayError> {
        let eoa = Address::random();
        let test_balance = U256::from(123456789u64);
        let Some(slot) = self.compute_slot(eoa) else { return Ok(Self::Unknown) };

        let result = provider
            .call(
                TransactionRequest::default()
                    .to(token_address)
                    .input(balanceOfCall { eoa }.abi_encode().into()),
            )
            .overrides(
                StateOverridesBuilder::default()
                    .append(
                        token_address,
                        AccountOverride::default()
                            .with_state_diff([(slot, B256::from(test_balance))]),
                    )
                    .build(),
            )
            .await?;

        let returned_balance = U256::from_be_slice(&result);
        if returned_balance != test_balance {
            warn!(
                token = %token_address,
                expected = %test_balance,
                got = %returned_balance,
                "Layout verification failed - balance mismatch"
            );
            return Ok(Self::Unknown);
        }

        debug!(token = %token_address, "Layout verification successful");
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{AssetDescriptor, AssetUid};
    use alloy::{
        contract::StorageSlotFinder, primitives::address, providers::ProviderBuilder,
        rpc::types::state::AccountOverride,
    };
    use std::collections::HashMap;

    #[tokio::test]
    async fn test_comprehensive_erc20_mapping_discovery() {
        let provider = ProviderBuilder::new()
            .connect("https://eu-central-mainnet.rpc.ithaca.xyz")
            .await
            .unwrap();

        // Create Assets with all test tokens
        let assets = Assets::new(HashMap::from_iter([
            (
                AssetUid::new("USDT".to_string()),
                AssetDescriptor {
                    address: address!("dAC17F958D2ee523a2206206994597C13D831ec7"),
                    decimals: 6,
                    fee_token: true,
                    interop: true,
                },
            ),
            (
                AssetUid::new("USDC".to_string()),
                AssetDescriptor {
                    address: address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"),
                    decimals: 6,
                    fee_token: true,
                    interop: true,
                },
            ),
            (
                AssetUid::new("DAI".to_string()),
                AssetDescriptor {
                    address: address!("6B175474E89094C44Da98b954EedeAC495271d0F"),
                    decimals: 18,
                    fee_token: true,
                    interop: true,
                },
            ),
        ]));

        // Initialize tracker with all tokens
        let tracker = Erc20Slots::new(&provider, &assets).await.expect("Should initialize tracker");

        // Test addresses to use for verification
        let test_addresses = vec![
            Address::ZERO,
            address!("0000000000000000000000000000000000000001"),
            address!("1234567890123456789012345678901234567890"),
        ];

        // Test tokens
        let tokens = [
            (address!("dAC17F958D2ee523a2206206994597C13D831ec7"), "USDT"),
            (address!("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"), "USDC"),
            (address!("6B175474E89094C44Da98b954EedeAC495271d0F"), "DAI"),
        ];

        // Verify all tokens discovered with proper layout (not Unknown)
        for (token_address, name) in &tokens {
            assert!(!tracker.is_unknown(*token_address), "{} should not be Unknown", name);
        }

        for (token_address, name) in tokens {
            // Verify slot computation matches StorageSlotFinder
            for test_addr in &test_addresses {
                let tracker_slot = tracker
                    .compute_balance_slot(&provider, token_address, *test_addr)
                    .await
                    .unwrap()
                    .unwrap_or_else(|| panic!("Should compute slot for {}", name));

                let slot_from_finder =
                    StorageSlotFinder::balance_of(&provider, token_address, *test_addr)
                        .with_request(TransactionRequest::default().gas_limit(100_000))
                        .find_slot()
                        .await
                        .expect("StorageSlotFinder should work")
                        .expect("Should find slot");

                assert_eq!(
                    slot_from_finder, tracker_slot,
                    "{}: Tracker slot should match StorageSlotFinder for address {:?}",
                    name, test_addr
                );
            }

            //  Test state override with tracker-computed slot
            let test_account = test_addresses[2];
            let slot = tracker
                .compute_balance_slot(&provider, token_address, test_account)
                .await
                .unwrap()
                .expect("Should compute slot");

            // Create state override to set balance
            let decimals = if name == "USDT" || name == "USDC" { 6 } else { 18 };
            let balance_value = U256::from(1337u64) * U256::from(10u64).pow(U256::from(decimals));

            let call_data = balanceOfCall { eoa: test_account }.abi_encode();
            let tx = TransactionRequest::default().to(token_address).input(call_data.into());

            let result = provider
                .call(tx)
                .overrides(
                    StateOverridesBuilder::default()
                        .append(
                            token_address,
                            AccountOverride::default()
                                .with_state_diff([(slot, B256::from(balance_value))]),
                        )
                        .build(),
                )
                .await
                .expect("Call should succeed with state override");

            let returned_balance = U256::from_be_slice(&result);
            assert_eq!(
                returned_balance, balance_value,
                "{}: State override balance should match",
                name
            );
        }
    }
}
