use std::ops::Not;

use crate::types::AssetMetadata;

use super::{
    AssetType,
    IERC20::{self},
    IERC721,
};
use alloy::primitives::{
    Address, ChainId, U256, address,
    map::{HashMap, HashSet},
};
use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChainAssetDiffs {
    /// USD value of the fee.
    pub fee_usd: f64,
    /// Asset diffs for this chain.
    pub asset_diffs: AssetDiffs,
}

/// Complete asset diff response containing multi chain asset diffs and aggregated fees in USD.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct AssetDiffResponse {
    /// Asset diffs per chain.
    pub chains: HashMap<ChainId, ChainAssetDiffs>,
    /// Total aggregated fee in USD.
    pub aggregated_fee_usd: f64,
}

impl AssetDiffResponse {
    /// Creates a new AssetDiffResponse with a single chain.
    pub fn new(chain_id: ChainId, chain_diffs: ChainAssetDiffs) -> Self {
        Self {
            aggregated_fee_usd: chain_diffs.fee_usd,
            chains: HashMap::from_iter([(chain_id, chain_diffs)]),
        }
    }

    /// Extends this response with another AssetDiffResponse.
    pub fn extend(&mut self, other: Self) {
        self.chains.extend(other.chains);
        self.aggregated_fee_usd += other.aggregated_fee_usd;
    }

    /// Adds a single chain's data to this response.
    pub fn push(&mut self, chain_id: ChainId, chain_diffs: ChainAssetDiffs) {
        self.aggregated_fee_usd += chain_diffs.fee_usd;
        self.chains.insert(chain_id, chain_diffs);
    }
}
