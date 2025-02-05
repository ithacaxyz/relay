use alloy::primitives::{Address, PrimitiveSignature, SignatureError, B256};
use serde::{Deserialize, Serialize};

/// A type that has been signed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signed<T> {
    #[serde(flatten)]
    ty: T,
    #[serde(flatten)]
    signature: PrimitiveSignature,
    hash: B256,
}

impl<T> Signed<T> {
    /// Instantiate from a type and signature. Does not verify the signature.
    pub const fn new_unchecked(ty: T, signature: PrimitiveSignature, hash: B256) -> Self {
        Self { ty, signature, hash }
    }

    /// Returns a reference to the type.
    pub const fn ty(&self) -> &T {
        &self.ty
    }

    /// Returns a reference to the signature.
    pub const fn signature(&self) -> &PrimitiveSignature {
        &self.signature
    }

    /// Returns a reference to the hash of the type.
    pub const fn hash(&self) -> &B256 {
        &self.hash
    }

    /// Splits the signed type into parts.
    pub fn into_parts(self) -> (T, PrimitiveSignature, B256) {
        (self.ty, self.signature, self.hash)
    }

    /// Returns the type without signature.
    pub fn strip_signature(self) -> T {
        self.ty
    }

    /// Recover the address of the signer.
    pub fn recover_address(&self) -> Result<Address, SignatureError> {
        self.signature().recover_address_from_prehash(self.hash())
    }
}
