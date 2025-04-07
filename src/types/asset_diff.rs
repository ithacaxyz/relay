use super::IERC20::{self, IERC20Events};
use alloy::{
    primitives::{Address, U256, address, aliases::I512, map::HashMap},
    rpc::types::Log,
    sol_types::{SolEvent, SolEventInterface},
};
use serde::{Deserialize, Serialize};

/// Net flow per account and asset based on simulated execution logs.
pub type AssetDiff = Vec<(Address, Vec<(Asset, I512)>)>;

/// Calculates the net asset difference for each account and asset based on logs.
///
/// This function processes logs by filtering for [`IERC20::Transfer`] events and accumulating
/// transfers as tuples of (credits, debits) for each account per asset.
///
/// After accumulating, each (credits, debits) tuple member is converted into a [I512] and finally
/// obtain the net flow of `credits - debits`.
///
/// # Notes
/// The native asset is represented by the address "0xeeee…eeee" as defined on `eth_simulateV1`.
pub fn calculate_asset_diff(logs: impl Iterator<Item = Log>) -> AssetDiff {
    let mut accounts: HashMap<Address, HashMap<Asset, (U256, U256)>> = HashMap::default();

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

    // Converts each credit and debit (U256) into I512, and calculates the resulting difference.
    accounts
        .into_iter()
        .map(|(address, assets)| {
            (
                address,
                assets
                    .into_iter()
                    .map(|(asset, (credits, debits))| {
                        let net = I512::try_from_le_slice(credits.as_le_slice())
                            .expect("should convert from u256")
                            - I512::try_from_le_slice(debits.as_le_slice())
                                .expect("should convert from u256");
                        (asset, net)
                    })
                    .collect(),
            )
        })
        .collect()
}

/// Asset coming from `eth_simulateV1` transfer logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Asset {
    /// Native asset.
    Native,
    /// ERC20 asset.
    ERC20(Address),
}

impl From<Address> for Asset {
    fn from(asset: Address) -> Self {
        // 0xee..ee is how `eth_simulateV1` represents the native asset.
        if asset == address!("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee") {
            Asset::Native
        } else {
            Asset::ERC20(asset)
        }
    }
}
