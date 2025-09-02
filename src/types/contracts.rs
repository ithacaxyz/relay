use crate::{
    config::RelayConfig, error::RelayError, types::DelegationProxy::DelegationProxyInstance,
};
use alloy::{primitives::Address, providers::Provider, sol, dyn_abi::Eip712Domain, transports::TransportErrorKind};
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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]

pub struct VersionedContract {
    /// Contract address.
    pub address: Address,
    /// Cached EIP712 domain.
    #[serde(skip)]
    pub eip712_domain: Option<Eip712Domain>,
}

impl VersionedContract {
    /// Creates a [`VersionedContract`].
    ///
    /// This fetches the contract version by calling `eip712Domain()` on the contract.
    pub async fn new<P: Provider>(address: Address, provider: P) -> Self {
        let domain = Eip712Contract::new(address, provider)
            .eip712Domain()
            .call()
            .await;

        match domain {
            Ok(domain) => {
                tracing::debug!(
                    name = %domain.name,
                    contract = %address,
                    version = %domain.version,
                    "Fetched EIP712 domain"
                );

                let eip712_domain = Eip712Domain {
                    name: Some(domain.name.into()),
                    version: Some(domain.version.into()),
                    chain_id: Some(domain.chainId),
                    verifying_contract: Some(domain.verifyingContract),
                    salt: Some(domain.salt),
                };

                Self { address, eip712_domain: Some(eip712_domain) }
            }
            Err(e) => {
                tracing::debug!(
                    contract = %address,
                    error = %e,
                    "Failed to fetch EIP712 domain"
                );
                Self { address, eip712_domain: None }
            }
        }
    }

    /// Creates a [`VersionedContract`] without a version.
    pub fn no_eip712_domain(address: Address) -> Self {
        Self { address, eip712_domain: None }
    }

    /// Returns the version from the cached EIP712 domain if available.
    pub fn version(&self) -> Option<String> {
        self.eip712_domain
            .as_ref()
            .and_then(|domain| domain.version.as_ref().map(|v| v.to_string()))
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
    /// Previously deployed orchestrators and simulators.
    pub legacy_orchestrators: Vec<VersionedOrchestratorContracts>,
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
            try_join_all(config.legacy_orchestrators.iter().map(async |&legacy| {
                tracing::debug!(
                    orchestrator = %legacy.orchestrator,
                    "Creating VersionedContract for legacy orchestrator"
                );
                let orchestrator = VersionedContract::new(legacy.orchestrator, provider).await;
                tracing::debug!(
                    simulator = %legacy.simulator,
                    "Creating VersionedContract for legacy simulator"
                );
                let simulator = VersionedContract::new(legacy.simulator, provider).await;
                Ok::<_, RelayError>(VersionedOrchestratorContracts { orchestrator, simulator })
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

        let orchestrator = async {
            tracing::debug!(
                orchestrator = %config.orchestrator,
                "Creating VersionedContract for current orchestrator"
            );
            Ok(VersionedContract::new(config.orchestrator, provider).await)
        };

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
            delegation_proxy: VersionedContract::no_eip712_domain(config.delegation_proxy),
            // TODO: These contracts have domains now
            simulator: VersionedContract::no_eip712_domain(config.simulator),
            funder: VersionedContract::no_eip712_domain(config.funder),
            escrow: VersionedContract::no_eip712_domain(config.escrow),
        })
    }
}

/// Orchestrator and simulator versioned contracts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionedOrchestratorContracts {
    /// Orchestrator contract.
    pub orchestrator: VersionedContract,
    /// Simulator contract.
    pub simulator: VersionedContract,
}
