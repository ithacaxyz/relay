use super::{
    AssetType,
    IERC20::{self},
    IERC721,
};
use crate::{
    error::{AssetError, RelayError},
    price::PriceOracle,
    types::{AssetMetadata, CoinKind, FeeTokens, Quote, Token},
};
use alloy::primitives::{
    Address, ChainId, U256, U512, address,
    map::{HashMap, HashSet},
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
    pub fn builder() -> AssetDiffBuilder {
        AssetDiffBuilder::default()
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
}

/// Asset with metadata and value diff.
#[serde_as]
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
    /// Value or id.
    pub value: U256,
    /// Incoming or outgoing direction.
    pub direction: DiffDirection,
    /// Optional fiat value
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fiat: Option<FiatValue>,
}

/// Fiat value representation
#[serde_as]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FiatValue {
    /// Currency code (e.g., "usd")
    pub currency: String,
    /// Value as f64
    #[serde_as(as = "DisplayFromStr")]
    pub value: f64,
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
        if asset == address!("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee") || asset == Address::ZERO
        {
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
pub struct AssetDiffBuilder {
    /// Assets seen in events.
    seen_assets: HashSet<Asset>,
    // For each account: fungible token credits/debits & non fungible token in/out.
    per_account: HashMap<Address, AccountChanges>,
}

#[derive(Debug, Default)]
struct AccountChanges {
    /// Account debits and credits per asset.
    fungible: HashMap<Asset, (U256, U256)>,
    /// Account nft sends and receives.
    non_fungible: HashSet<(Asset, DiffDirection, U256)>,
}

impl AssetDiffBuilder {
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
                .filter(|(asset, change, _)| change.is_incoming() && asset.is_native().not())
                // Safe to call .address() since we filter off native assets.
                .map(|(asset, _, id)| (asset.address(), *id))
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
            .and_modify(|(c, _)| *c += transfer.amount)
            .or_insert((transfer.amount, U256::ZERO));

        // debits
        self.per_account
            .entry(transfer.from)
            .or_default()
            .fungible
            .entry(asset)
            .and_modify(|(_, d)| *d += transfer.amount)
            .or_insert((U256::ZERO, transfer.amount));
    }

    /// Records a [`IERC721::Transfer`] event.
    pub fn record_erc721(&mut self, asset: Asset, transfer: IERC721::Transfer) {
        self.seen_assets.insert(asset);

        for &(eoa, diff) in &[
            (transfer.from, DiffDirection::Outgoing), // sent
            (transfer.to, DiffDirection::Incoming),   // received
        ] {
            // we are only interested in collapsed/net diffs. When a eoa sends and
            // receives the same NFT, it should not have an entry.
            //
            // * if there is no other diff: insert it
            // * if the eoa is sending, but there is a diff with a receiving event: just remove
            //   existing
            // * if the eoa is receiving, but there is a diff with a sending event: just remove
            //   existing

            let nft_set = &mut self.per_account.entry(eoa).or_default().non_fungible;

            if !nft_set.remove(&(asset, diff.opposite(), transfer.id)) {
                nft_set.insert((asset, diff, transfer.id));
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
            for (asset, (credit, debit)) in changes.fungible {
                // skip zero‐net
                if credit == debit {
                    continue;
                }

                let (direction, value) = if credit > debit {
                    (DiffDirection::Incoming, credit - debit)
                } else {
                    (DiffDirection::Outgoing, debit - credit)
                };

                let info = &metadata[&asset];

                account_diffs.push(AssetDiff {
                    token_kind: asset.is_native().not().then_some(AssetType::ERC20),
                    address: asset.is_native().not().then(|| asset.address()),
                    metadata: info.metadata.clone(),
                    value,
                    direction,
                    fiat: None,
                });
            }

            // non-fungible tokens
            for (asset, direction, id) in changes.non_fungible {
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
    /// Determines the correct coin kind for USD price lookup.
    fn coin_for_usd(token: &Token, chain_id: ChainId) -> CoinKind {
        if token.address.is_zero() { CoinKind::native_for_chain(chain_id) } else { token.kind }
    }

    /// Creates a new ChainAssetDiffs with populated fiat values and calculated fee USD.
    pub async fn new(
        mut asset_diffs: AssetDiffs,
        quote: &Quote,
        fee_tokens: &FeeTokens,
        price_oracle: &PriceOracle,
    ) -> Result<Self, RelayError> {
        let chain_id = quote.chain_id;
        let fee_token = quote.intent.paymentToken;
        let fee_amount = quote.intent.totalPaymentAmount;

        // Calculate fee USD value
        let token = fee_tokens
            .find(chain_id, &fee_token)
            .ok_or_else(|| RelayError::Asset(AssetError::UnknownFeeToken(fee_token)))?;

        let native_coin = Self::coin_for_usd(token, chain_id);
        let usd_price = price_oracle
            .usd_price(native_coin)
            .await
            .ok_or_else(|| RelayError::Asset(AssetError::PriceUnavailable(native_coin)))?;

        let fee_usd = calculate_usd_value(fee_amount, usd_price, token.decimals);

        // Populate fiat values for asset diffs
        join_all(
            asset_diffs
                .0
                .iter_mut()
                .flat_map(|(_, diffs)| diffs.iter_mut())
                .filter(|diff| diff.metadata.decimals.is_some())
                .map(async |diff| {
                    let Some(token) =
                        fee_tokens.find(chain_id, &diff.address.unwrap_or(Address::ZERO))
                    else {
                        return;
                    };

                    let native_coin = Self::coin_for_usd(token, chain_id);
                    let Some(usd_price) = price_oracle.usd_price(native_coin).await else { return };

                    diff.fiat = Some(FiatValue {
                        currency: "usd".to_string(),
                        value: calculate_usd_value(
                            diff.value,
                            usd_price,
                            diff.metadata.decimals.expect("qed"),
                        ),
                    });
                }),
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
    pub fee_totals: HashMap<ChainId, FiatValue>,
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
            FiatValue { currency: "usd".to_string(), value: chain_diffs.fee_usd },
        );
        self.asset_diffs.insert(chain_id, chain_diffs.asset_diffs);

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

        self.fee_totals.insert(0, FiatValue { currency: "usd".to_string(), value: total });
    }
}

/// Helper function to calculate USD value from token amount and price.
pub fn calculate_usd_value(amount: U256, usd_price: f64, decimals: u8) -> f64 {
    let result = U512::from(amount).saturating_mul(U512::from(usd_price * 1e18))
        / U512::from(10u128.pow(decimals as u32));
    result.to::<u128>() as f64 / 1e18
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
            fiat: Some(FiatValue { currency: "usd".to_string(), value: 100.50 }),
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
            }
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
            }
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
    }
}
