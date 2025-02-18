//! Multi-signer abstraction.
//!
//! A signer abstracted over multiple underlying signers, e.g. local or AWS.
use alloy::{
    dyn_abi::Eip712Domain,
    network::{FullSigner, TxSigner},
    primitives::{Address, Bytes, PrimitiveSignature, B256},
    signers::{aws::AwsSigner, local::PrivateKeySigner},
    sol_types::SolStruct,
};
use aws_config::BehaviorVersion;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use std::{fmt, ops::Deref, str::FromStr, sync::Arc};

/// Abstraction over local signer or AWS.
pub struct DynSigner(pub Arc<dyn FullSigner<PrimitiveSignature> + Send + Sync>);

impl fmt::Debug for DynSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RelaySigner").field(&self.address()).finish()
    }
}

impl DynSigner {
    /// Load a private key or AWS signer from environment variables
    pub async fn load(key: &str, chain_id: Option<u64>) -> eyre::Result<Self> {
        if let Ok(wallet) = PrivateKeySigner::from_str(key) {
            return Ok(Self(Arc::new(wallet)));
        }

        let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let client = aws_sdk_kms::Client::new(&config);
        Ok(Self(Arc::new(AwsSigner::new(client, key.to_string(), chain_id).await?)))
    }

    /// Encodes and signs the typed data according to [EIP-712].
    ///
    /// [EIP-712]: https://eips.ethereum.org/EIPS/eip-712
    pub async fn sign_typed_data<T: SolStruct + Send + Sync>(
        &self,
        payload: &T,
        domain: &Eip712Domain,
    ) -> eyre::Result<Bytes> {
        Ok(self.sign_hash(&payload.eip712_signing_hash(domain)).await?.as_bytes().into())
    }

    /// Returns the signer's Ethereum Address.
    pub fn address(&self) -> Address {
        TxSigner::address(&self.0)
    }
}

impl Deref for DynSigner {
    type Target = dyn FullSigner<PrimitiveSignature> + Send + Sync;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

/// Abstraction over P256 signer.
#[derive(Debug)]
pub struct P256Signer(pub Arc<p256::ecdsa::SigningKey>);

impl P256Signer {
    /// Load a P256 key
    pub fn load(key: &B256) -> eyre::Result<Self> {
        Ok(Self(Arc::new(p256::ecdsa::SigningKey::from_slice(key.as_slice())?)))
    }

    /// Encodes and signs the typed data according to [EIP-712].
    ///
    /// [EIP-712]: https://eips.ethereum.org/EIPS/eip-712
    pub async fn sign_typed_data<T: SolStruct + Send + Sync>(
        &self,
        payload: &T,
        domain: &Eip712Domain,
    ) -> eyre::Result<Bytes> {
        Ok(self
            .0
            .sign_prehash(payload.eip712_signing_hash(domain).as_slice())
            .map(|signature: p256::ecdsa::Signature| signature.normalize_s().unwrap_or(signature))?
            .to_bytes()
            .to_vec()
            .into())
    }

    /// Returns the signer's k256 public key in [`Bytes`].
    pub fn public_key(&self) -> Bytes {
        self.0.verifying_key().to_encoded_point(false).to_bytes()[1..].to_vec().into()
    }
}
