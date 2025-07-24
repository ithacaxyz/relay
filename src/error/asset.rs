use super::internal_rpc;
use thiserror::Error;

/// Errors related to assets.
#[derive(Debug, Error)]
pub enum AssetError {
    /// The response on querying information from assets was invalid.
    #[error("call response for the asset info query was invalid.")]
    InvalidAssetInfoResponse,
    /// The asset info service is unavailable.
    #[error("the asset info service is unavailable.")]
    ServiceUnavailable,
    /// The fee token is not known.
    #[error("unknown fee token")]
    UnknownFeeToken,
    /// The price for the asset is unavailable.
    #[error("price unavailable")]
    PriceUnavailable,
}

impl From<AssetError> for jsonrpsee::types::error::ErrorObject<'static> {
    fn from(err: AssetError) -> Self {
        match err {
            AssetError::InvalidAssetInfoResponse
            | AssetError::ServiceUnavailable
            | AssetError::UnknownFeeToken
            | AssetError::PriceUnavailable => internal_rpc(err.to_string()),
        }
    }
}
