//! P256 signer type with webauthn capabilities used for gas estimation and testing.

use super::Eip712PayLoadSigner;
use alloy::primitives::{B256, Bytes};
use p256::ecdsa::{SigningKey, signature::hazmat::PrehashSigner};
use std::sync::Arc;

/// Trait for all signers that use a [`SigningKey`] underneath..
pub trait P256Key {
    /// Return reference to the P256 signing key.
    fn signing_key(&self) -> &SigningKey;

    /// Signs a prehashed digest with the p256 key.
    fn sign_prehash(&self, digest: &[u8]) -> eyre::Result<p256::ecdsa::Signature> {
        Ok(self
            .signing_key()
            .sign_prehash(digest)
            .map(|s: p256::ecdsa::Signature| s.normalize_s().unwrap_or(s))?)
    }

    /// Returns the signer's p256 public key in [`Bytes`].
    fn public_key(&self) -> Bytes {
        self.signing_key().verifying_key().to_encoded_point(false).to_bytes()[1..].to_vec().into()
    }
}

impl P256Key for P256Signer {
    fn signing_key(&self) -> &SigningKey {
        &self.0
    }
}

/// Abstraction over a P256 signer with webauthn capabilities.
#[derive(Debug)]
pub struct P256Signer(pub Arc<SigningKey>);

impl P256Signer {
    /// Load a P256 key
    pub fn load(key: &B256) -> eyre::Result<Self> {
        Ok(Self(Arc::new(SigningKey::from_slice(key.as_slice())?)))
    }
}

#[async_trait::async_trait]
impl Eip712PayLoadSigner for P256Signer {
    async fn sign_payload_hash(&self, payload_hash: B256) -> eyre::Result<Bytes> {
        Ok(self.sign_prehash(payload_hash.as_slice())?.to_bytes().to_vec().into())
    }
}
