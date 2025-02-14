//! Multi-signer abstraction.
//!
//! A signer abstracted over multiple underlying signers, e.g. local or AWS.
use alloy::{
    network::{FullSigner, TxSigner},
    primitives::{Address, PrimitiveSignature},
    signers::{aws::AwsSigner, local::PrivateKeySigner},
};
use aws_config::BehaviorVersion;
use std::{fmt, ops::Deref, str::FromStr, sync::Arc};

/// Abstraction over local signer or AWS.
pub struct Signer(pub Arc<dyn FullSigner<PrimitiveSignature> + Send + Sync>);

impl fmt::Debug for Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RelaySigner").field(&self.address()).finish()
    }
}

impl Signer {
    /// Load a private key or AWS signer from environment variables.
    pub async fn load(key: &str, chain_id: Option<u64>) -> eyre::Result<Self> {
        if let Ok(wallet) = PrivateKeySigner::from_str(key) {
            return Ok(Self(Arc::new(wallet)));
        }

        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let client = aws_sdk_kms::Client::new(&config);
        Ok(Self(Arc::new(AwsSigner::new(client, key.to_string(), chain_id).await?)))
    }

    /// Returns the signer's Ethereum Address.
    pub fn address(&self) -> Address {
        TxSigner::address(&self.0)
    }
}

impl Deref for Signer {
    type Target = dyn FullSigner<PrimitiveSignature> + Send + Sync;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}
