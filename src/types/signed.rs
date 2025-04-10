use alloy::primitives::{Address, B256, Signature, SignatureError};
use serde::{Deserialize, Serialize};

/// A type that has been signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Signed<T> {
    #[serde(flatten)]
    ty: T,
    #[serde(flatten)]
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
