use super::IERC20::{self, IERC20Events};
use crate::{asset::AssetInfoServiceHandle, error::RelayError};
use alloy::{
    primitives::{
        Address, U256, address,
        aliases::I512,
        map::{HashMap, HashSet},
    },
    providers::Provider,
    rpc::types::Log,
    sol_types::{SolEvent, SolEventInterface},
};
use serde::{Deserialize, Serialize};

/// Net flow per account and asset based on simulated execution logs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetDiffs(Vec<(Address, Vec<AssetDiff>)>);

impl AssetDiffs {
    /// Calculates the net asset difference for each account and asset based on logs.
    ///
    /// This function processes logs by filtering for [`IERC20::Transfer`] events and accumulating
    /// transfers as tuples of (credits, debits) for each account per asset.
    ///
    /// After accumulating, each (credits, debits) tuple member is converted into a [I512] and
    /// finally obtain the net flow of `credits - debits`.
    ///
    /// # Notes
    /// The native asset is represented by the address "0xeeee…eeee" as defined on `eth_simulateV1`.
    pub async fn new<P: Provider>(
        logs: impl Iterator<Item = Log>,
        asset_info_handle: AssetInfoServiceHandle,
        provider: &P,
    ) -> Result<AssetDiffs, RelayError> {
        let mut accounts: HashMap<Address, HashMap<Asset, (U256, U256)>> = HashMap::default();

        let mut assets = HashSet::new();
        for log in logs {
            if log.topic0() != Some(&IERC20::Transfer::SIGNATURE_HASH) {
                continue;
            }

            let Some((asset, transfer)) =
                IERC20Events::decode_log(&log.inner, true).ok().map(|ev| match ev.data {
                    IERC20Events::Transfer(transfer) => (Asset::from(log.inner.address), transfer),
                })
            else {
                continue;
            };

            // Need to collect all assets so we can fetch their metadata
            assets.insert(asset);

            // For the receiver, add transfer.amount to credits.
            accounts
                .entry(transfer.to)
                .or_default()
                .entry(asset)
                .and_modify(|(credit, _)| *credit += transfer.amount)
                .or_insert((transfer.amount, U256::ZERO));

            // For the sender, add transfer.amount to debits.
            accounts
                .entry(transfer.from)
                .or_default()
                .entry(asset)
                .and_modify(|(_, debit)| *debit += transfer.amount)
                .or_insert((U256::ZERO, transfer.amount));
        }

        let assets_map =
            asset_info_handle.get_asset_info_list(&provider, assets.into_iter().collect()).await?;

        // Converts each credit and debit (U256) into I512, and calculates the resulting difference.
        Ok(Self(
            accounts
                .into_iter()
                .map(|(address, assets)| {
                    (
                        address,
                        assets
                            .into_iter()
                            .map(|(asset, (credits, debits))| {
                                let value = I512::try_from_le_slice(credits.as_le_slice())
                                    .expect("should convert from u256")
                                    - I512::try_from_le_slice(debits.as_le_slice())
                                        .expect("should convert from u256");

                                // `get_asset_info_list` ensures we have the asset
                                let AssetWithInfo { name, symbol, decimals, .. } =
                                    assets_map.get(&asset).cloned().expect("should have");

                                AssetDiff {
                                    address: (!asset.is_native()).then(|| asset.address()),
                                    name,
                                    symbol,
                                    decimals,
                                    value,
                                }
                            })
                            .collect(),
                    )
                })
                .collect(),
        ))
    }
}

/// Asset with metadata and value diff.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssetDiff {
    /// Asset address. `None` represents the native token.
    address: Option<Address>,
    /// Asset name.
    name: Option<String>,
    /// Asset symbol.
    symbol: Option<String>,
    /// Asset decimals.
    decimals: Option<u8>,
    /// Value diff.
    value: I512,
}

/// Asset coming from `eth_simulateV1` transfer logs.
///
/// Note: Token variant might not be ERC20.
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
