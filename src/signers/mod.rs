//! Relay signers.

mod r#dyn;
use alloy::primitives::{Bytes, B256};
pub use r#dyn::DynSigner;

mod p256;
pub use p256::{P256Key, P256Signer};

mod webauthn;
pub use webauthn::WebAuthnSigner;

/// Trait for a [EIP-712] payload signer.
#[async_trait::async_trait]
pub trait Eip712PayLoadSigner: std::fmt::Debug + Send {
    /// Signs the [EIP-712] payload hash.
    ///
    /// Returns [`Bytes`].
    async fn sign_payload_hash(&self, payload_hash: B256) -> eyre::Result<Bytes>;
}
