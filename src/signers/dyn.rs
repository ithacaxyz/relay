//! Multi-signer abstraction.
//!
//! A signer abstracted over multiple underlying signers.
use super::Eip712PayLoadSigner;
use alloy::{
    network::{FullSigner, TxSigner},
    primitives::{Address, B256, Bytes, Signature},
    signers::{
        aws::AwsSigner,
        k256::ecdsa::SigningKey,
        local::{
            PrivateKeySigner,
            coins_bip39::{English, Mnemonic},
        },
    },
};
use aws_config::BehaviorVersion;
use std::{fmt, ops::Deref, str::FromStr, sync::Arc};

/// Abstraction over local signer.
#[derive(Clone)]
pub struct DynSigner(pub Arc<dyn FullSigner<Signature> + Send + Sync>);

impl fmt::Debug for DynSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RelaySigner").field(&self.address()).finish()
    }
}

impl DynSigner {
    /// Derives given number of signers from a mnemonic.
    pub fn derive_from_mnemonic(
        mnemonic: Mnemonic<English>,
        num: usize,
    ) -> eyre::Result<Vec<Self>> {
        (0..num)
            .map(|idx| {
                let path = format!("m/44'/60'/0'/0/{idx}");
                let key = mnemonic.derive_key(path.as_str(), None)?;
                let key: &SigningKey = key.as_ref();
                Ok(Self(Arc::new(PrivateKeySigner::from_signing_key(key.clone()))))
            })
            .collect()
    }

    /// Load a private key.
    pub async fn from_signing_key(key: &str) -> eyre::Result<Self> {
        Ok(Self(Arc::new(PrivateKeySigner::from_str(key)?)))
    }

    /// Load a signer from AWS KMS.
    pub async fn from_kms(key_id: &str, chain_id: Option<u64>) -> eyre::Result<Self> {
        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let client = aws_sdk_kms::Client::new(&config);
        Ok(Self(Arc::new(AwsSigner::new(client, key_id.to_string(), chain_id).await?)))
    }

    /// Returns the signer's Ethereum Address.
    pub fn address(&self) -> Address {
        TxSigner::address(&self.0)
    }
}

impl Deref for DynSigner {
    type Target = dyn FullSigner<Signature> + Send + Sync;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

#[async_trait::async_trait]
impl Eip712PayLoadSigner for DynSigner {
    async fn sign_payload_hash(&self, payload_hash: B256) -> eyre::Result<Bytes> {
        Ok(self.sign_hash(&payload_hash).await?.as_bytes().into())
    }
}
