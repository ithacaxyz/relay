use super::{
    IERC20::{self},
    IERC721, TokenKind,
};
use alloy::primitives::{
    Address, U256, address,
    aliases::I512,
    map::{HashMap, HashSet},
};
use serde::{Deserialize, Serialize};

/// Net flow per account and asset based on simulated execution logs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetDiffs(pub Vec<(Address, Vec<AssetDiff>)>);

impl AssetDiffs {
    /// Returns a [`AssetDiffBuilder`] that can build [`AssetDiffs`].
    pub fn builder() -> AssetDiffBuilder {
        AssetDiffBuilder::default()
    }

    /// By default, asset diffs include the user op payment. This ensures it gets removed.
    pub fn subtract_payer_fee(&mut self, payer: Address, asset: Address, fee: U256) {
        let fee = I512::try_from_le_slice(fee.as_le_slice()).expect("u256→i512");

        // Asset diff expects a None asset address if dealing with the native token.
        let asset = (!asset.is_zero()).then_some(asset);

        self.0.retain_mut(|(eoa, diffs)| {
            if eoa == &payer {
                // only retain diffs with non zero values
                diffs.retain_mut(|diff| {
                    if diff.address != asset {
                        return true;
                    }
                    diff.value -= fee;

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
    pub token_kind: Option<TokenKind>,
    /// Asset name.
    pub name: Option<String>,
    /// Asset symbol.
    pub symbol: Option<String>,
    /// TokenURI if it exists.
    pub uri: Option<String>,
    /// Asset decimals.
    pub decimals: Option<u8>,
    /// Value diff.
    pub value: I512,
}

/// Asset coming from `eth_simulateV1` transfer logs.
///
/// Note: Token variant might not be a token contract.
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
}

impl From<Address> for Asset {
    fn from(asset: Address) -> Self {
        // 0xee..ee is how `eth_simulateV1` represents the native asset.
        if asset == address!("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee") {
            Asset::Native
        } else {
            Asset::Token(asset)
        }
    }
}

/// Represents metadata for an asset.
#[derive(Debug, Clone)]
pub struct AssetWithInfo {
    /// Asset.
    pub asset: Asset,
    /// Name.
    pub name: Option<String>,
    /// Symbol.
    pub symbol: Option<String>,
    /// Decimals.
    pub decimals: Option<u8>,
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
    /// Account nft sends (negative id value) and receives (positive id value).
    non_fungible: HashSet<(Asset, I512)>,
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
                .filter(|(asset, change)| change.is_positive() && !asset.is_native())
                // Safe to cast, since IDs were originally U256.
                // Safe to call .address() since we filter off native assets.
                .map(|(asset, id)| {
                    (asset.address(), U256::from_le_slice(&id.to_le_bytes::<64>()[..32]))
                })
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

        let id = I512::try_from_le_slice(transfer.id.as_le_slice()).expect("u256→i512");

        for &(eoa, diff) in &[
            (transfer.from, -id), // sent
            (transfer.to, id),    // received
        ] {
            // we are only interested in collapsed/net diffs. When a eoa sends and
            // receives the same NFT, it should not have an entry.
            //
            // * if there is no other diff: insert it
            // * if the eoa is sending (negative number), but there is a diff with a receiving event
            //   (positive number): just remove existing
            // * if the eoa is receiving (positive number), but there is a diff with a sending event
            //   (negative number): just remove existing

            let nft_set = &mut self.per_account.entry(eoa).or_default().non_fungible;

            if !nft_set.remove(&(asset, -diff)) {
                nft_set.insert((asset, diff));
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
                let net = I512::try_from_le_slice(credit.as_le_slice()).expect("u256→i512")
                    - I512::try_from_le_slice(debit.as_le_slice()).expect("u256→i512");

                if net.is_zero() {
                    continue;
                }

                let info = &metadata[&asset];
                account_diffs.push(AssetDiff {
                    token_kind: (!asset.is_native()).then_some(TokenKind::ERC20),
                    address: (!asset.is_native()).then(|| asset.address()),
                    name: info.name.clone(),
                    symbol: info.symbol.clone(),
                    decimals: info.decimals,
                    uri: None,
                    value: net,
                });
            }

            // non-fungible tokens
            for (asset, id) in changes.non_fungible {
                let info = &metadata[&asset];
                let uri = (!asset.is_native())
                    .then(|| (asset.address(), U256::from_le_slice(&id.to_le_bytes::<64>()[..32])))
                    .and_then(|key| tokens_uris.get(&key).cloned())
                    .flatten();

                account_diffs.push(AssetDiff {
                    token_kind: (!asset.is_native()).then_some(TokenKind::ERC721),
                    address: (!asset.is_native()).then(|| asset.address()),
                    name: info.name.clone(),
                    symbol: info.symbol.clone(),
                    uri,
                    decimals: info.decimals,
                    value: id,
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
