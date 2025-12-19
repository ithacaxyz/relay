//! Relay signers.

mod r#dyn;
use alloy::primitives::{B256, Bytes};
pub use r#dyn::DynSigner;

mod p256;
pub use p256::{P256Key, P256Signer};

mod webauthn;
pub use webauthn::WebAuthnSigner;

use crate::types::KeyType;

/// Trait for a [EIP-712] payload signer.
#[async_trait::async_trait]
pub trait Eip712PayLoadSigner: std::fmt::Debug + Send + Sync {
    /// Returns the key type.
    fn key_type(&self) -> KeyType;

    /// Signs the [EIP-712] payload hash.
    ///
    /// Returns [`Bytes`].
    async fn sign_payload_hash(&self, payload_hash: B256) -> eyre::Result<Bytes>;
}
