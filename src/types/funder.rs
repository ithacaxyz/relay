//! Funder contract interface.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::signers::DynSigner;
use IFunder::{IFunderInstance, Withdrawal, withdrawTokensWithSignatureCall};
use alloy::{
    dyn_abi::Eip712Domain,
    primitives::{Address, U256},
    providers::Provider,
    sol,
    sol_types::SolStruct,
};

sol! {
    #[sol(rpc)]
    #[derive(Debug)]
    interface IFunder {
        struct Withdrawal {
            address token;
            address recipient;
            uint256 amount;
            uint256 deadline;
            uint256 nonce;
        }

        function withdrawTokensWithSignature(
            address token,
            address recipient,
            uint256 amount,
            uint256 deadline,
            uint256 nonce,
            bytes calldata signature
        ) external;

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

        function pullGas(uint256 amount) external;
        function setGasWallet(address[] memory wallets, bool isGasWallet);
        function gasWallets(address wallet) external returns (bool);

        function owner() external view returns (address);
    }
}

/// Funder contract instance.
#[derive(Debug)]
pub struct Funder<P> {
    inner: IFunderInstance<P>,
}

impl<P: Provider> Funder<P> {
    /// Create a new [`Funder`] instance.
    pub fn new(address: Address, provider: P) -> Self {
        Self { inner: IFunder::new(address, provider) }
    }

    /// Get the [`Eip712Domain`] for this funder.
    pub async fn eip712_domain(&self) -> alloy::contract::Result<Eip712Domain> {
        let domain = self.inner.eip712Domain().call().await?;

        Ok(Eip712Domain::new(
            Some(domain.name.into()),
            Some(domain.version.into()),
            Some(domain.chainId),
            Some(domain.verifyingContract),
            None,
        ))
    }

    /// Prepares a [`withdrawTokensWithSignatureCall`] call.
    pub async fn withdrawal_call(
        &self,
        token: Address,
        recipient: Address,
        amount: U256,
        owner: &DynSigner,
    ) -> eyre::Result<withdrawTokensWithSignatureCall> {
        let nonce = U256::random();
        let deadline =
            U256::from(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 600);

        let payload = Withdrawal { token, recipient, amount, deadline, nonce };
        let signature =
            owner.sign_hash(&payload.eip712_signing_hash(&self.eip712_domain().await?)).await?;

        Ok(withdrawTokensWithSignatureCall {
            token,
            recipient,
            amount,
            nonce,
            deadline,
            signature: signature.as_bytes().into(),
        })
    }
}
