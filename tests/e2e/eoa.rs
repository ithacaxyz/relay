use alloy::{
    primitives::{Address, U256},
    sol_types::SolCall,
};
use relay::{
    signers::DynSigner,
    types::{Call, IDelegation::authorizeCall, KeyWith712Signer, PREPAccount},
};

/// Kind of EOA: PREP or Upgraded.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum EoaKind {
    Upgraded(DynSigner),
    Prep { admin_key: KeyWith712Signer, account: PREPAccount },
}

impl EoaKind {
    /// Create a new [`EoaKind`] with [`DynSigner`].
    pub fn create_upgraded(signer: DynSigner) -> Self {
        Self::Upgraded(signer)
    }

    /// Create a new [`EoaKind`] with [`PREPAccount`].
    pub fn create_prep(admin_key: KeyWith712Signer, delegation: Address) -> Self {
        let init_data = vec![Call {
            target: Address::ZERO,
            value: U256::ZERO,
            data: authorizeCall { key: admin_key.key().clone() }.abi_encode().into(),
        }];

        let account = PREPAccount::initialize(delegation, init_data.clone());

        Self::Prep { admin_key, account }
    }

    /// Returns a reference to the inner [DynSigner] when dealing with an upgraded account.
    ///
    /// # Panics
    ///
    /// This will panic if it's not an upgraded account.
    pub fn root_signer(&self) -> &DynSigner {
        match self {
            EoaKind::Upgraded(dyn_signer) => dyn_signer,
            EoaKind::Prep { admin_key, account } => {
                panic!("eoa is not an upgraded account")
            }
        }
    }

    /// Returns a reference to the inner [KeyWith712Signer] when dealing with a PREP account.
    ///
    /// # Panics
    ///
    /// This will panic if it's not a PREP account.
    pub fn prep_signer(&self) -> &KeyWith712Signer {
        match self {
            EoaKind::Upgraded(dyn_signer) => panic!("eoa is not a prep account"),
            EoaKind::Prep { admin_key, account } => admin_key,
        }
    }

    /// Whether self is a PREP account.
    pub fn is_prep(&self) -> bool {
        matches!(self, Self::Prep { .. })
    }

    /// Returns [Address].
    pub fn address(&self) -> Address {
        match self {
            EoaKind::Upgraded(dyn_signer) => dyn_signer.address(),
            EoaKind::Prep { account, .. } => account.address,
        }
    }
}
