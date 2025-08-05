use crate::{
    config::RelayConfig, error::RelayError, types::DelegationProxy::DelegationProxyInstance,
};
use alloy::{primitives::Address, providers::Provider, sol, transports::TransportErrorKind};
use futures_util::future::try_join_all;
use serde::{Deserialize, Serialize};
use tokio::try_join;

sol! {
    #[sol(rpc)]
    interface Eip712Contract {
        /// Returns the EIP712 domain of the delegation.
        ///
        /// See: https://eips.ethereum.org/EIPS/eip-5267
        function eip712Domain()
            public
            view
            virtual
            returns (
                bytes1 fields,
                string memory name,
                string memory version,
                uint256 chainId,
                address verifyingContract,
                bytes32 salt,
                uint256[] memory extensions
            );
    }
}

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
    ///
    /// This fetches the contract version by calling `eip712Domain()` on the contract.
    pub async fn new<P: Provider>(address: Address, provider: P) -> Self {
        let version = Eip712Contract::new(address, provider)
            .eip712Domain()
            .call()
            .await
            .map(|domain| domain.version)
            .ok();

        Self { address, version }
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
    /// Orchestrator.
    pub orchestrator: VersionedContract,
    /// The delegation implementation.
    ///
    /// This is directly fetched from the proxy.
    #[serde(rename = "accountImplementation")]
    pub delegation_implementation: VersionedContract,
    /// Previously deployed orchestrators.
    pub legacy_orchestrators: Vec<VersionedContract>,
    /// Previously deployed delegation implementations.
    #[serde(rename = "legacyAccountImplementations")]
    pub legacy_delegations: Vec<VersionedContract>,
    /// Delegation proxy.
    #[serde(rename = "accountProxy")]
    pub delegation_proxy: VersionedContract,
    /// Simulator.
    pub simulator: VersionedContract,
    /// Funder.
    pub funder: VersionedContract,
    /// Escrow.
    pub escrow: VersionedContract,
}

impl VersionedContracts {
    /// Generates a [`VersionedContracts`] from [`RelayConfig`].
    pub async fn new<P: Provider>(config: &RelayConfig, provider: &P) -> Result<Self, RelayError> {
        let legacy_orchestrators =
            try_join_all(config.legacy_orchestrators.iter().map(async |&address| {
                Ok::<_, RelayError>(VersionedContract::new(address, provider).await)
            }));

        let legacy_delegations =
            try_join_all(config.legacy_delegation_proxies.iter().map(async |&proxy_address| {
                let implementation = DelegationProxyInstance::new(proxy_address, provider)
                    .implementation()
                    .call()
                    .await
                    .map_err(TransportErrorKind::custom)?;

                Ok(VersionedContract::new(implementation, provider).await)
            }));

        let orchestrator =
            async { Ok(VersionedContract::new(config.orchestrator, provider).await) };

        let delegation_implementation = async {
            let delegation_implementation =
                DelegationProxyInstance::new(config.delegation_proxy, provider)
                    .implementation()
                    .call()
                    .await
                    .map_err(TransportErrorKind::custom)?;

            Ok(VersionedContract::new(delegation_implementation, provider).await)
        };

        let (legacy_orchestrators, legacy_delegations, orchestrator, delegation_implementation) = try_join!(
            legacy_orchestrators,
            legacy_delegations,
            orchestrator,
            delegation_implementation
        )?;

        Ok(Self {
            orchestrator,
            delegation_implementation,
            legacy_orchestrators,
            legacy_delegations,
            delegation_proxy: VersionedContract::no_version(config.delegation_proxy),
            simulator: VersionedContract::no_version(config.simulator),
            funder: VersionedContract::no_version(config.funder),
            escrow: VersionedContract::no_version(config.escrow),
        })
    }
}
