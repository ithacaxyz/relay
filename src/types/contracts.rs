use crate::{
    config::RelayConfig,
    error::RelayError,
    types::{Account, DelegationProxy::DelegationProxyInstance, Entry},
};
use alloy::{primitives::Address, providers::Provider, transports::TransportErrorKind};
use futures_util::future::try_join_all;
use serde::{Deserialize, Serialize};
use tokio::try_join;

/// Contract address with optional version.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct VersionedContract {
    /// Contract address.
    pub address: Address,
    /// Contract version.
    #[serde(default)]
    pub version: Option<String>,
}

impl VersionedContract {
    /// Creates a [`VersionedContract`].
    pub fn new(address: Address, version: String) -> Self {
        Self { address, version: Some(version) }
    }

    /// Creates a [`VersionedContract`] without a version.
    pub fn no_version(address: Address) -> Self {
        Self { address, version: None }
    }
}

/// Relay versioned contracts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VersionedContracts {
    /// Entrypoint.
    pub entrypoint: VersionedContract,
    /// The delegation implementation.
    ///
    /// This is directly fetched from the proxy.
    pub delegation_implementation: VersionedContract,
    /// Previously deployed entrypoints.
    pub legacy_entrypoints: Vec<VersionedContract>,
    /// Previously deployed delegation implementations.
    pub legacy_delegations: Vec<VersionedContract>,
    /// Delegation proxy.
    pub delegation_proxy: VersionedContract,
    /// Account registry.
    pub account_registry: VersionedContract,
    /// Simulator.
    pub simulator: VersionedContract,
}

impl VersionedContracts {
    /// Generates a [`VersionedContracts`] from [`RelayConfig`].
    pub async fn new<P: Provider>(config: &RelayConfig, provider: &P) -> Result<Self, RelayError> {
        let legacy_entrypoints =
            try_join_all(config.legacy_entrypoints.iter().map(async |&address| {
                Ok::<_, RelayError>(VersionedContract::new(
                    address,
                    Entry::new(address, provider).version().await?,
                ))
            }));

        let legacy_delegations =
            try_join_all(config.legacy_delegations.iter().map(async |&address| {
                Ok(VersionedContract::new(
                    address,
                    Account::new(address, provider).version().await?,
                ))
            }));

        let entrypoint = async {
            Ok(VersionedContract::new(
                config.entrypoint,
                Entry::new(config.entrypoint, provider).version().await?,
            ))
        };

        let delegation_implementation = async {
            let delegation_implementation =
                DelegationProxyInstance::new(config.delegation_proxy, provider)
                    .implementation()
                    .call()
                    .await
                    .map_err(TransportErrorKind::custom)?;

            Ok(VersionedContract::new(
                delegation_implementation,
                Account::new(delegation_implementation, provider).version().await?,
            ))
        };

        let (legacy_entrypoints, legacy_delegations, entrypoint, delegation_implementation) = try_join!(
            legacy_entrypoints,
            legacy_delegations,
            entrypoint,
            delegation_implementation
        )?;

        Ok(Self {
            entrypoint,
            delegation_implementation,
            legacy_entrypoints,
            legacy_delegations,
            delegation_proxy: VersionedContract::no_version(config.delegation_proxy),
            account_registry: VersionedContract::no_version(config.account_registry),
            simulator: VersionedContract::no_version(config.simulator),
        })
    }
}
