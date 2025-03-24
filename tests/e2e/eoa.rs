use alloy::{
    primitives::{Address, B256, U256},
    sol_types::SolCall,
};
use relay::{
    signers::{DynSigner, Eip712PayLoadSigner},
    types::{
        Call, CreatableAccount, IDelegation::authorizeCall, KeyHashWithID, KeyType,
        KeyWith712Signer, PREPAccount,
    },
};

/// Kind of EOA: PREP or Upgraded.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum EoaKind {
    Upgraded(DynSigner),
    Prep { admin_key: KeyWith712Signer, account: CreatableAccount },
}

impl EoaKind {
    /// Create a new [`EoaKind`] with [`DynSigner`].
    pub fn create_upgraded(signer: DynSigner) -> Self {
        Self::Upgraded(signer)
    }

    /// Create a new [`EoaKind`] with [`PREPAccount`].
    pub async fn create_prep(
        admin_key: KeyWith712Signer,
        delegation: Address,
    ) -> eyre::Result<Self> {
        let init_calls = vec![Call {
            target: Address::ZERO,
            value: U256::ZERO,
            data: authorizeCall { key: admin_key.key().clone() }.abi_encode().into(),
        }];

        let prep = PREPAccount::initialize(delegation, init_calls);
        let key_hash = admin_key.key_hash();
        let hash = admin_key.identifier_digest(prep.address);

        let signature = match admin_key.keyType {
            KeyType::P256 => {
                panic!("P256 can only be a session key.")
            }
            KeyType::WebAuthnP256 => {
                let ephemeral = DynSigner::load(&B256::random().to_string(), None).await?;
                ephemeral.sign_payload_hash(hash).await?
            }
            KeyType::Secp256k1 => admin_key.sign_payload_hash(hash).await?,
            _ => unreachable!(),
        };

        Ok(Self::Prep {
            admin_key,
            account: CreatableAccount::new(
                prep,
                vec![KeyHashWithID { hash: key_hash, id_signature: signature }],
            ),
        })
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

    /// Returns a reference to the inner [`KeyWith712Signer`] when dealing with a PREP account.
    ///
    /// # Panics
    ///
    /// This will panic if it's not a PREP account.
    pub fn prep_signer(&self) -> &KeyWith712Signer {
        match self {
            EoaKind::Upgraded(_dyn_signer) => panic!("eoa is not a prep account"),
            EoaKind::Prep { admin_key, .. } => admin_key,
        }
    }

    /// Whether self is a PREP account.
    pub fn is_prep(&self) -> bool {
        matches!(self, Self::Prep { .. })
    }

    /// Returns [`Address`].
    pub fn address(&self) -> Address {
        match self {
            EoaKind::Upgraded(dyn_signer) => dyn_signer.address(),
            EoaKind::Prep { account, .. } => account.prep.address,
        }
    }
}
