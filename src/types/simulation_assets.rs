//! Asset diff tracking for transaction simulation and execution.

use crate::{
    asset::{self, AssetInfoServiceHandle},
    chains::Chains,
    constants::SIMULATEV1_NATIVE_ADDRESS,
    error::{AssetError, RelayError},
    price::{PriceOracle, calculate_usd_value},
    types::{
        AssetMetadata, AssetPrice, AssetType, IERC20, IERC20::IERC20Events, IERC721,
        IERC721::IERC721Events, Quote,
    },
};
use alloy::{
    primitives::{
        Address, B256, ChainId, U256,
        map::{HashMap, HashSet},
    },
    providers::{Provider, ext::DebugApi},
    rpc::types::trace::geth::{CallConfig, GethDebugTracingOptions},
    sol_types::SolEventInterface,
    transports::TransportErrorKind,
};
use futures_util::future::join_all;
use serde::{Deserialize, Serialize};
use serde_with::{DisplayFromStr, serde_as};
use std::ops::Not;

/// Net flow per account and asset based on simulated execution logs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetDiffs(pub Vec<(Address, Vec<AssetDiff>)>);

impl AssetDiffs {
    /// Returns a [`AssetDiffBuilder`] that can build [`AssetDiffs`].
    pub fn builder() -> AssetDiffsBuilder {
        AssetDiffsBuilder::default()
    }

    /// Extracts asset diffs from a confirmed transaction's trace.
    ///
    /// Uses `debug_traceTransaction` to analyze ERC20/ERC721 transfer events
    /// and builds asset diffs with complete metadata.
    pub async fn from_trace_transaction<P: Provider>(
        provider: &P,
        tx_hash: B256,
        asset_info: &AssetInfoServiceHandle,
    ) -> Result<Self, RelayError> {
        let trace_options = GethDebugTracingOptions::call_tracer(CallConfig::default().with_log());

        let trace = provider.debug_trace_transaction(tx_hash, trace_options).await?;
        let call_frame = trace.try_into_call_frame().map_err(|e| {
            TransportErrorKind::custom_str(&format!("Failed to extract call frame from trace: {e}"))
        })?;

        // Collect logs from the call frame
        let (_, logs) = crate::types::simulator::collect_calls_and_logs_from_frame(call_frame);

        // Build asset diffs from logs
        let builder = AssetDiffsBuilder::from_logs(&logs);

        // Fetch metadata for seen assets
        let seen_assets: Vec<_> = builder.seen_assets().copied().collect();
        let seen_nfts: Vec<_> = builder.seen_nfts().collect();

        let (metadata, tokens_uris) = tokio::try_join!(
            asset_info.get_asset_info_list(provider, seen_assets),
            asset::fetch_nft_uris(provider, &seen_nfts)
        )?;

        Ok(builder.build(metadata, tokens_uris))
    }

    /// By default, asset diffs include the intent payment. This ensures it gets removed.
    pub fn remove_payer_fee(&mut self, payer: Address, asset: Asset, fee: U256) {
        // Asset diff expects a None asset address if dealing with the native token.
        let asset = asset.is_native().not().then(|| asset.address());

        self.0.retain_mut(|(eoa, diffs)| {
            if eoa == &payer {
                // only retain diffs with non zero values
                diffs.retain_mut(|diff| {
                    if diff.address != asset {
                        return true;
                    }

                    if diff.direction.is_outgoing() {
                        // net was outgoing: remove fee
                        if diff.value > fee {
                            // still outgoing
                            diff.value -= fee;
                        } else {
                            // flip to incoming with leftover
                            diff.direction = DiffDirection::Incoming;
                            diff.value = fee - diff.value;
                        }
                    } else {
                        // net was incoming: just add the fee
                        diff.value += fee;
                    }

                    !diff.value.is_zero()
                });
            }
            // only retain entries with asset diffs
            !diffs.is_empty()
        });
    }

    /// Returns a mutable iterator over all asset diffs across all addresses.
    fn asset_diffs_iter_mut(&mut self) -> impl Iterator<Item = &mut AssetDiff> {
        self.0.iter_mut().flat_map(|(_, diffs)| diffs.iter_mut())
    }
}

/// Asset with metadata and value diff.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetDiff {
    /// Asset address. `None` represents the native token.
    pub address: Option<Address>,
    /// Token kind. ERC20 or ERC721.
    #[serde(rename = "type")]
    pub token_kind: Option<AssetType>,
    /// Token metadata.
    #[serde(flatten)]
    pub metadata: AssetMetadata,
    /// ERC-20 value or ERC-721 token ID.
    pub value: U256,
    /// Incoming or outgoing direction.
    pub direction: DiffDirection,
    /// Optional fiat value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fiat: Option<AssetPrice>,
    /// List of recipients for this asset diff.
    pub recipients: Vec<Address>,
}

impl AssetDiff {
    /// Checks if this asset diff can be merged with another (same asset).
    fn can_merge(&self, other: &AssetDiff) -> bool {
        self.address == other.address
    }

    /// Merges another asset diff into this one by combining values based on direction.
    fn merge(&mut self, other: AssetDiff) {
        if self.direction == other.direction {
            self.value += other.value;
        } else if other.value > self.value {
            self.value = other.value - self.value;
            self.direction = other.direction;
        } else {
            self.value -= other.value;
        }

        self.fiat = other.fiat;

        for recipient in other.recipients {
            if !self.recipients.contains(&recipient) {
                self.recipients.push(recipient);
            }
        }
    }
}

/// Asset deficits per account based on simulated execution traces.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetDeficits(pub Vec<AssetDeficit>);

impl AssetDeficits {
    /// Returns true if the asset deficits are empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Removes the specified amount from the deficit for the given fee token.
    /// If the deficit becomes zero or negative, removes that asset deficit entirely.
    pub fn remove_fee_amount(&mut self, fee_token: Address, amount: U256) {
        self.0.retain_mut(|deficit| {
            if deficit.address != Some(fee_token) {
                return true;
            }

            if deficit.deficit <= amount {
                return false;
            }

            deficit.deficit -= amount;
            deficit.required -= amount;
            true
        });
    }
}

/// Asset with metadata and deficit value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssetDeficit {
    /// Asset address. `None` represents the native token.
    pub address: Option<Address>,
    /// Token metadata.
    #[serde(flatten)]
    pub metadata: AssetMetadata,
    /// Required balance of the asset.
    pub required: U256,
    /// Asset deficit.
    pub deficit: U256,
    /// Optional fiat value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fiat: Option<AssetPrice>,
}

/// Asset coming from `eth_simulateV1` transfer logs.
///
/// Note: Asset variant might not be a token contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Asset {
    /// Native asset.
    Native,
    /// Token asset.
    Token(Address),
}

impl Asset {
    /// Infers the asset type from the given address.
    ///
    /// If the address is address 0 or `0xEeE..eEe` it is native, otherwise it is a token.
    pub fn infer_from_address(address: Address) -> Self {
        if address.is_zero() || address == SIMULATEV1_NATIVE_ADDRESS {
            Self::native()
        } else {
            Self::token(address)
        }
    }

    /// Create a native asset.
    pub fn native() -> Self {
        Self::Native
    }

    /// Create a token asset.
    pub fn token(address: Address) -> Self {
        Self::Token(address)
    }

    /// Whether it is the native asset from a chain.
    pub fn is_native(&self) -> bool {
        matches!(self, Self::Native)
    }

    /// Returns the address
    ///
    /// # Panics
    /// It will panic if self is of the native variant.
    pub fn address(&self) -> Address {
        match self {
            Asset::Native => panic!("only token assets can return an address"),
            Asset::Token(address) => *address,
        }
    }

    /// Creates an Asset from an optional address.
    ///
    /// If the address is `Some`, converts it to a token asset.
    /// If the address is `None`, returns the native asset.
    pub fn from_address(address: Option<Address>) -> Self {
        if let Some(address) = address { Self::Token(address) } else { Self::Native }
    }
}

impl From<Address> for Asset {
    fn from(asset: Address) -> Self {
        // 0xee..ee is how `eth_simulateV1` represents the native asset, and 0x00..00 is how we
        // represent the native asset.
        if asset == SIMULATEV1_NATIVE_ADDRESS || asset == Address::ZERO {
            Asset::Native
        } else {
            Asset::Token(asset)
        }
    }
}

impl From<Option<Address>> for Asset {
    fn from(asset: Option<Address>) -> Self {
        if let Some(asset) = asset { asset.into() } else { Asset::Native }
    }
}

/// Represents metadata for an asset.
#[derive(Debug, Clone)]
pub struct AssetWithInfo {
    /// Asset.
    pub asset: Asset,
    /// Asset metadata.
    pub metadata: AssetMetadata,
}

/// Builds a collapsed diff for both fungible & non-fungible tokens into [`AssetDiff`].
#[derive(Debug, Default)]
pub struct AssetDiffsBuilder {
    /// Assets seen in events.
    seen_assets: HashSet<Asset>,
    // For each account: fungible token credits/debits & non fungible token in/out.
    per_account: HashMap<Address, AccountChanges>,
}

/// Tracks fungible token transfers for an asset.
#[derive(Debug, Default)]
struct FungibleTransfer {
    /// Total amount credited to the account.
    credit: U256,
    /// Total amount debited from the account.
    debit: U256,
    /// Recipients when this account sends tokens (only tracked for debits).
    recipients: HashSet<Address>,
}

/// Tracks non-fungible token transfers.
#[derive(Debug, Clone)]
struct NftTransfer {
    /// Recipient for outgoing transfers (None for incoming).
    recipient: Option<Address>,
}

#[derive(Debug, Default)]
struct AccountChanges {
    /// Account debits and credits per asset.
    fungible: HashMap<Asset, FungibleTransfer>,
    /// Account nft sends and receives, keyed by (asset, direction, id) so we can easily look up
    /// the opposite direction of nft transfers.
    non_fungible: HashMap<(Asset, DiffDirection, U256), NftTransfer>,
}

impl AssetDiffsBuilder {
    /// Creates an `AssetDiffsBuilder` from logs by decoding ERC20 and ERC721 Transfer events.
    pub fn from_logs(logs: &[alloy::primitives::Log]) -> Self {
        let mut builder = Self::default();
        for log in logs {
            // ERC-20
            if let Some((asset, transfer)) =
                IERC20Events::decode_log(log).ok().map(|ev| match ev.data {
                    IERC20Events::Transfer(t) => (Asset::from(log.address), t),
                })
            {
                builder.record_erc20(asset, transfer);
            }
            // ERC-721
            else if let Some((asset, transfer)) =
                IERC721Events::decode_log(log).ok().map(|ev| match ev.data {
                    IERC721Events::Transfer(t) => (Asset::from(log.address), t),
                })
            {
                builder.record_erc721(asset, transfer);
            }
        }
        builder
    }

    /// Returns an iterator over seen assets.
    pub fn seen_assets(&self) -> impl Iterator<Item = &Asset> {
        self.seen_assets.iter()
    }

    /// Returns an iterator over seen nfts.
    pub fn seen_nfts(&self) -> impl Iterator<Item = (Address, U256)> {
        self.per_account.iter().flat_map(|(_, changes)| {
            changes
                .non_fungible
                .iter()
                .filter(|((asset, direction, _), _)| {
                    direction.is_incoming() && asset.is_native().not()
                })
                // Safe to call .address() since we filter off native assets.
                .map(|((asset, _, id), _)| (asset.address(), *id))
        })
    }

    /// Records a [`IERC20::Transfer`] event.
    pub fn record_erc20(&mut self, asset: Asset, transfer: IERC20::Transfer) {
        self.seen_assets.insert(asset);

        // credits
        self.per_account
            .entry(transfer.to)
            .or_default()
            .fungible
            .entry(asset)
            .or_default()
            .credit += transfer.amount;

        // debits and track recipient
        let debit_entry =
            self.per_account.entry(transfer.from).or_default().fungible.entry(asset).or_default();

        debit_entry.debit += transfer.amount;
        debit_entry.recipients.insert(transfer.to);
    }

    /// Records a [`IERC721::Transfer`] event.
    pub fn record_erc721(&mut self, asset: Asset, transfer: IERC721::Transfer) {
        self.seen_assets.insert(asset);

        for (eoa, diff, recipient) in [
            (transfer.from, DiffDirection::Outgoing, Some(transfer.to)), // sent
            (transfer.to, DiffDirection::Incoming, None),                // received
        ] {
            // We are only interested in collapsed/net diffs. When an eoa sends and
            // receives the same NFT, it should not have an entry.
            //
            // * if the eoa is sending, but there is a diff with a receiving event: just remove
            //   existing
            // * if the eoa is receiving, but there is a diff with a sending event: just remove
            //   existing

            let nft_map = &mut self.per_account.entry(eoa).or_default().non_fungible;
            let key = (asset, diff, transfer.id);
            let opposite_key = (asset, diff.opposite(), transfer.id);

            if nft_map.remove(&opposite_key).is_none() {
                // No opposite direction exists, so insert this one
                nft_map.insert(key, NftTransfer { recipient });
            }
        }
    }

    /// Builds and returns [`AssetDiffs`].
    pub fn build(
        self,
        metadata: HashMap<Asset, AssetWithInfo>,
        tokens_uris: HashMap<(Address, U256), Option<String>>,
    ) -> AssetDiffs {
        let mut entries = Vec::with_capacity(self.per_account.len());

        for (eoa, changes) in self.per_account {
            let mut account_diffs =
                Vec::with_capacity(changes.fungible.len() + changes.non_fungible.len());

            // fungible tokens
            for (asset, transfer) in changes.fungible {
                // skip zero‐net
                if transfer.credit == transfer.debit {
                    continue;
                }

                let (direction, value, recipients) = if transfer.credit > transfer.debit {
                    (DiffDirection::Incoming, transfer.credit - transfer.debit, Vec::new())
                } else {
                    (
                        DiffDirection::Outgoing,
                        transfer.debit - transfer.credit,
                        transfer.recipients.into_iter().collect(),
                    )
                };

                let info = &metadata[&asset];

                account_diffs.push(AssetDiff {
                    token_kind: asset.is_native().not().then_some(AssetType::ERC20),
                    address: asset.is_native().not().then(|| asset.address()),
                    metadata: info.metadata.clone(),
                    value,
                    direction,
                    fiat: None,
                    recipients,
                });
            }

            // non-fungible tokens
            for ((asset, direction, id), nft) in changes.non_fungible {
                let info = &metadata[&asset];
                let uri = asset
                    .is_native()
                    .not()
                    .then(|| (asset.address(), id))
                    .and_then(|key| tokens_uris.get(&key).cloned())
                    .flatten();

                account_diffs.push(AssetDiff {
                    token_kind: asset.is_native().not().then_some(AssetType::ERC721),
                    address: asset.is_native().not().then(|| asset.address()),
                    metadata: AssetMetadata { uri, ..info.metadata.clone() },
                    value: id,
                    direction,
                    fiat: None,
                    recipients: nft.recipient.into_iter().collect(),
                });
            }

            // only include accounts that actually changed
            if !account_diffs.is_empty() {
                entries.push((eoa, account_diffs));
            }
        }

        AssetDiffs(entries)
    }
}

/// Direction of an asset diff from a EOA perspective.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiffDirection {
    /// Incoming asset.
    Incoming,
    /// Outgoing asset.
    Outgoing,
}

impl DiffDirection {
    /// Return the opposite direction.
    pub fn opposite(&self) -> Self {
        match self {
            DiffDirection::Incoming => DiffDirection::Outgoing,
            DiffDirection::Outgoing => DiffDirection::Incoming,
        }
    }

    /// Whether it's incoming.
    pub fn is_incoming(&self) -> bool {
        matches!(self, Self::Incoming)
    }

    /// Whether it's outgoing.
    pub fn is_outgoing(&self) -> bool {
        matches!(self, Self::Outgoing)
    }
}

/// Chain-specific asset diffs and fee in USD.
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainAssetDiffs {
    /// USD value of the fee.
    #[serde_as(as = "DisplayFromStr")]
    pub fee_usd: f64,
    /// Asset diffs for this chain.
    pub asset_diffs: AssetDiffs,
}

impl ChainAssetDiffs {
    /// Creates a new ChainAssetDiffs with populated fiat values and calculated fee USD.
    pub async fn new(
        mut asset_diffs: AssetDiffs,
        quote: &Quote,
        chains: &Chains,
        price_oracle: &PriceOracle,
    ) -> Result<Self, RelayError> {
        let chain_id = quote.chain_id;
        let fee_token = quote.intent.payment_token();
        let fee_amount = quote.intent.total_payment_amount();

        // Calculate fee USD value
        let (token_uid, token) = chains
            .fee_token(chain_id, fee_token)
            .ok_or_else(|| RelayError::Asset(AssetError::UnknownFeeToken(fee_token)))?;
        let usd_price = price_oracle
            .usd_conversion_rate(token_uid.clone())
            .await
            .ok_or_else(|| RelayError::Asset(AssetError::PriceUnavailable(token_uid.clone())))?;

        let fee_usd = calculate_usd_value(fee_amount, usd_price, token.decimals);

        // Populate fiat values for asset diffs
        join_all(
            asset_diffs.asset_diffs_iter_mut().filter(|diff| diff.metadata.decimals.is_some()).map(
                async |diff| {
                    let Some((token_uid, _)) =
                        chains.fee_token(chain_id, diff.address.unwrap_or(Address::ZERO))
                    else {
                        return;
                    };
                    let Some(usd_price) = price_oracle.usd_conversion_rate(token_uid.clone()).await
                    else {
                        return;
                    };

                    diff.fiat = Some(AssetPrice {
                        currency: "usd".to_string(),
                        value: calculate_usd_value(
                            diff.value,
                            usd_price,
                            diff.metadata.decimals.expect("qed"),
                        ),
                    });
                },
            ),
        )
        .await;
        Ok(Self { fee_usd, asset_diffs })
    }
}

/// Complete asset diff response containing multi chain asset diffs and aggregated fees in USD.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AssetDiffResponse {
    /// Fee totals by chain ID:
    ///
    /// - Individual chain fees: Each chain's fee is stored under its actual chain ID.
    /// - Aggregated total: Chain ID 0 is a special key that stores the sum of all individual chain
    ///   fees.
    #[serde(with = "alloy::serde::quantity::hashmap")]
    pub fee_totals: HashMap<ChainId, AssetPrice>,
    /// Asset diffs by chain ID.
    ///
    /// Note: There is no aggregated entry for asset diffs (no chain ID 0).
    #[serde(with = "alloy::serde::quantity::hashmap")]
    pub asset_diffs: HashMap<ChainId, AssetDiffs>,
}

impl AssetDiffResponse {
    /// Creates a new instance with a single chain.
    pub fn new(chain_id: ChainId, chain_diffs: ChainAssetDiffs) -> Self {
        let mut response = Self::default();
        response.push(chain_id, chain_diffs);
        response
    }

    /// Extends this response with other.
    pub fn extend(&mut self, other: Self) {
        for (chain_id, chain_diffs) in other.asset_diffs {
            self.asset_diffs.insert(chain_id, chain_diffs);
        }

        for (chain_id, fee) in other.fee_totals {
            if chain_id != 0 {
                self.fee_totals.insert(chain_id, fee);
            }
        }

        self.update_aggregated_fee();
    }

    /// Adds a single chain's data to this response.
    pub fn push(&mut self, chain_id: ChainId, chain_diffs: ChainAssetDiffs) {
        self.fee_totals.insert(
            chain_id,
            AssetPrice { currency: "usd".to_string(), value: chain_diffs.fee_usd },
        );
        self.asset_diffs.insert(chain_id, chain_diffs.asset_diffs);

        self.update_aggregated_fee();
    }

    /// Merges additional asset diffs into this response on the specified chain.
    pub fn merge(&mut self, chain_id: ChainId, chain_diffs: ChainAssetDiffs) {
        let existing = self.asset_diffs.entry(chain_id).or_insert_with(|| AssetDiffs(Vec::new()));

        for (address, new_diffs) in chain_diffs.asset_diffs.0 {
            if let Some((_, existing_diffs)) =
                existing.0.iter_mut().find(|(addr, _)| *addr == address)
            {
                // Merge each new diff with existing diffs for the same address
                for new_diff in new_diffs {
                    if let Some(existing_diff) =
                        existing_diffs.iter_mut().find(|d| d.can_merge(&new_diff))
                    {
                        existing_diff.merge(new_diff);
                    } else {
                        existing_diffs.push(new_diff);
                    }
                }
                // Remove any diffs that became zero after merging
                existing_diffs.retain(|d| !d.value.is_zero());
            } else {
                existing.0.push((address, new_diffs));
            }
        }

        self.fee_totals
            .entry(chain_id)
            .and_modify(|fee| fee.value += chain_diffs.fee_usd)
            .or_insert(AssetPrice { currency: "usd".to_string(), value: chain_diffs.fee_usd });
        self.update_aggregated_fee();
    }

    /// Updates the aggregated fee total at chain ID 0 by summing all chain fees.
    ///
    /// Chain ID 0 is reserved for the aggregated total, while individual chains use their actual
    /// IDs.
    fn update_aggregated_fee(&mut self) {
        let total: f64 = self
            .fee_totals
            .iter()
            .filter(|(chain_id, _)| **chain_id != 0)
            .map(|(_, fiat)| fiat.value)
            .sum();

        self.fee_totals.insert(0, AssetPrice { currency: "usd".to_string(), value: total });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;
    use serde_json::json;

    #[test]
    fn test_asset_diff_serialization() {
        let asset_diff = AssetDiff {
            address: Some(address!("0x1234567890123456789012345678901234567890")),
            token_kind: Some(AssetType::ERC20),
            metadata: AssetMetadata {
                name: Some("Test Token".to_string()),
                symbol: Some("TEST".to_string()),
                decimals: Some(18),
                uri: None,
            },
            value: U256::from(1000000000000000000u64), // 1e18
            direction: DiffDirection::Incoming,
            fiat: Some(AssetPrice { currency: "usd".to_string(), value: 100.50 }),
            recipients: vec![],
        };

        let serialized = serde_json::to_value(&asset_diff).unwrap();

        let expected = json!({
            "address": "0x1234567890123456789012345678901234567890",
            "type": "erc20",
            "name": "Test Token",
            "symbol": "TEST",
            "decimals": 18,
            "value": "0xde0b6b3a7640000",
            "direction": "incoming",
            "fiat": {
                "currency": "usd",
                "value": "100.5"
            },
            "recipients": []
        });

        assert_eq!(serialized, expected);
    }

    #[test]
    fn test_asset_diff_deserialization() {
        let json = json!({
            "address": "0x1234567890123456789012345678901234567890",
            "type": "erc20",
            "name": "Test Token",
            "symbol": "TEST",
            "decimals": 18,
            "value": "0xde0b6b3a7640000",
            "direction": "outgoing",
            "fiat": {
                "currency": "usd",
                "value": "50.25"
            },
            "recipients": ["0x9876543210987654321098765432109876543210"]
        });

        let asset_diff: AssetDiff = serde_json::from_value(json).unwrap();

        assert_eq!(
            asset_diff.address,
            Some(address!("0x1234567890123456789012345678901234567890"))
        );
        assert_eq!(asset_diff.token_kind, Some(AssetType::ERC20));
        assert_eq!(asset_diff.metadata.name, Some("Test Token".to_string()));
        assert_eq!(asset_diff.metadata.symbol, Some("TEST".to_string()));
        assert_eq!(asset_diff.metadata.decimals, Some(18));
        assert_eq!(asset_diff.value, U256::from(1000000000000000000u64));
        assert_eq!(asset_diff.direction, DiffDirection::Outgoing);
        assert_eq!(asset_diff.fiat.as_ref().unwrap().currency, "usd");
        assert_eq!(asset_diff.fiat.as_ref().unwrap().value, 50.25);
        assert_eq!(asset_diff.recipients.len(), 1);
        assert_eq!(
            asset_diff.recipients[0],
            address!("0x9876543210987654321098765432109876543210")
        );
    }
}
