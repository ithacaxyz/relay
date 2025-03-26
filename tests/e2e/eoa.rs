use alloy::primitives::Address;
use relay::{signers::DynSigner, types::CreatableAccount};

/// Kind of EOA: PREP or Upgraded.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum EoaKind {
    Upgraded(DynSigner),
    Prep(Option<CreatableAccount>),
}

impl EoaKind {
    /// Create a new [`EoaKind`] with [`DynSigner`].
    pub fn create_upgraded(signer: DynSigner) -> Self {
        Self::Upgraded(signer)
    }

    /// Create a new [`EoaKind`] with [`CreatableAccount`].
    pub fn create_prep() -> Self {
        Self::Prep(None)
    }

    /// Returns a reference to the inner [`DynSigner`] when dealing with an upgraded account.
    ///
    /// # Panics
    ///
    /// This will panic if it's not an upgraded account.
    pub fn root_signer(&self) -> &DynSigner {
        match self {
            EoaKind::Upgraded(dyn_signer) => dyn_signer,
            EoaKind::Prep { .. } => {
                panic!("eoa is not an upgraded account")
            }
        }
    }

    /// Whether self is a PREP account.
    pub fn is_prep(&self) -> bool {
        matches!(self, Self::Prep { .. })
    }

    /// Returns [`Address`].
    ///
    /// # Panics
    ///
    /// It will panic if the account has not been yet created when dealing with
    /// [`CreatableAccount`].
    pub fn address(&self) -> Address {
        match self {
            EoaKind::Upgraded(dyn_signer) => dyn_signer.address(),
            EoaKind::Prep(account) => {
                account.as_ref().expect("prep not calculated yet").prep.address
            }
        }
    }
}
