use std::collections::HashMap;

use alloy::{
    primitives::{Address, ChainId},
    providers::Provider,
    transports::TransportResult,
};
use serde::{Deserialize, Serialize};

use crate::types::{AssetType, rpc::AddressOrNative};

/// A provider extension for `wallet_` APIs.
///
/// Currently implements the following ERCs:
///
/// - [ERC-7811](https://eips.ethereum.org/EIPS/eip-7811): Wallet Asset Discovery
pub trait WalletProviderExt {
    async fn get_assets(&self, request: AssetRequest) -> TransportResult<HashMap<ChainId, Asset>>;
}

impl<T> WalletProviderExt for T
where
    T: Provider,
{
    /// Gets all assets for the given account, optionally filtered.
    ///
    /// If `asset_filter` is provided, then only the requested assets will be returned, and the
    /// other two filters (`asset_type_filter` and `chain_filter`) are ignored entirely as outlined
    /// in the ERC.
    ///
    /// In the case that no filter is provided whatsoever, nothing is returned, as the provider
    /// cannot provide a sane default. If you want to provide a default, use
    /// `AssetRequest::with_default` to provide a default when no filters are specified.
    ///
    /// For more information, see [ERC-7811](https://eips.ethereum.org/EIPS/eip-7811).
    ///
    /// # Note
    ///
    /// The provider will only return assets for the chain it connects to, meaning a request that
    /// only asks for assets on a chain the provider is not connected to is effectively a no-op.
    ///
    /// # Note on multicall
    ///
    /// This method requires multicall3 to be available.
    fn get_assets(
        &self,
        request: AssetRequest,
    ) -> impl Future<Output = TransportResult<HashMap<ChainId, Asset>>> {
        async { Ok(()) }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AssetRequest {
    account: Address,
    asset_filter: Option<AssetFilter>,
    #[serde(default)]
    asset_type_filter: Vec<AssetType>,
    #[serde(default)]
    chain_filter: Vec<ChainId>, // todo: hex
    #[serde(skip)]
    default_filter: Option<AssetFilter>,
}

impl AssetRequest {
    /// Set the default asset filter to use if no filter is specified.
    ///
    /// More concretely, if neither of `asset_filter`, `asset_type_filter` or `chain_filter` is set,
    /// this filter is used.
    pub fn with_default(&mut self, default_filter: AssetFilter) -> &mut Self {
        self.default_filter = Some(default_filter);
        self
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AssetFilter {
    filter: HashMap<ChainId, Asset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    address: AddressOrNative,
    #[serde(rename = "type")]
    kind: AssetType,
}
