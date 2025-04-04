use super::IERC20::{self, IERC20Events};
use alloy::{
    primitives::{Address, U256, address, aliases::I512, map::HashMap},
    rpc::types::Log,
    sol_types::{SolEvent, SolEventInterface},
};
use serde::{Deserialize, Serialize};

/// Net asset flow per asset and account based on simulated execution logs.
pub type AssetDiff = Vec<(Asset, Vec<(Address, I512)>)>;

/// Calculates the net asset difference for each asset and account based on logs.
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
    let asset_diff = logs
        .filter_map(|log| {
            if log.topic0()? == &IERC20::Transfer::SIGNATURE_HASH {
                match IERC20Events::decode_log(&log.inner, true).ok()?.data {
                    IERC20Events::Transfer(transfer) => {
                        return Some((Asset::from(log.inner.address), transfer));
                    }
                }
            }
            None
        })
        .fold(HashMap::new(), |mut credits_and_debits, (asset, transfer)| {
            let asset: &mut HashMap<Address, (U256, U256)> =
                credits_and_debits.entry(asset).or_default();

            // For the receiver, add transfer.amount to credits.
            asset
                .entry(transfer.to)
                .and_modify(|(credit, _)| *credit += transfer.amount)
                .or_insert((transfer.amount, U256::ZERO));

            // For the sender, add transfer.amount to debits.
            asset
                .entry(transfer.from)
                .and_modify(|(_, debit)| *debit += transfer.amount)
                .or_insert((U256::ZERO, transfer.amount));

            credits_and_debits
        });

    // Converts each credit and debit (U256) into I512, and then calculates the resulting
    // net.
    asset_diff
        .into_iter()
        .map(|(asset, inner)| {
            (
                asset,
                inner
                    .into_iter()
                    .map(|(account, (credits, debits))| {
                        // Convert U256 to I512 and compute net = credits - debits.
                        let net = I512::try_from_le_slice(credits.as_le_slice())
                            .expect("should convert from u256")
                            - I512::try_from_le_slice(debits.as_le_slice())
                                .expect("should convert from u256");
                        (account, net)
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
