use alloy::primitives::{Address, B256, Sealable, Signature, SignatureError};
use serde::{Deserialize, Serialize};

/// A type that has been signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Signed<T> {
    ty: T,
    signature: Signature,
    hash: B256,
}

impl<T> Signed<T> {
    /// Instantiate from a type and signature. Does not verify the signature.
    pub const fn new_unchecked(ty: T, signature: Signature, hash: B256) -> Self {
        Self { ty, signature, hash }
    }

    /// Returns a reference to the type.
    pub const fn ty(&self) -> &T {
        &self.ty
    }

    /// Returns a mutable reference to the type.
    pub const fn ty_mut(&mut self) -> &mut T {
        &mut self.ty
    }

    /// Returns a reference to the signature.
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Returns a reference to the hash of the type.
    pub const fn hash(&self) -> &B256 {
        &self.hash
    }

    /// Recover the address of the signer.
    pub fn recover_address(&self) -> Result<Address, SignatureError> {
        self.signature().recover_address_from_prehash(self.hash())
    }
}

mod serde_impl {
    use super::*;
    use serde::de::DeserializeOwned;
    use std::borrow::Cow;

    #[derive(Serialize, Deserialize)]
    struct SerdeHelper<'a, T: Clone> {
        #[serde(flatten)]
        ty: Cow<'a, T>,
        #[serde(flatten)]
        signature: Signature,
        #[serde(skip_deserializing)]
        hash: Option<B256>,
    }

    impl<T: Clone + Serialize> Serialize for Signed<T> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer,
        {
            let Self { ty, signature, hash } = self;
            SerdeHelper { ty: Cow::Borrowed(ty), signature: *signature, hash: Some(*hash) }
                .serialize(serializer)
        }
    }

    impl<'de, T: Clone + Sealable + DeserializeOwned> Deserialize<'de> for Signed<T> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let SerdeHelper::<T> { ty, signature, hash: _ } =
                SerdeHelper::deserialize(deserializer)?;
            let hash = ty.hash_slow();
            Ok(Self::new_unchecked(ty.into_owned(), signature, hash))
        }
    }
}
