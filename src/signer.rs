//! Multi-signer abstraction.
//!
//! A signer abstracted over multiple underlying signers, e.g. local or AWS.
use crate::types::KeyType;
use alloy::{
    dyn_abi::Eip712Domain,
    hex,
    network::{FullSigner, TxSigner},
    primitives::{Address, Bytes, PrimitiveSignature},
    signers::{aws::AwsSigner, local::PrivateKeySigner},
    sol_types::SolStruct,
};
use aws_config::BehaviorVersion;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use std::{fmt, ops::Deref, str::FromStr, sync::Arc};

/// Abstraction over local signer or AWS.
pub struct DynSigner {
    /// Transaction signer.
    pub tx_signer: Arc<dyn FullSigner<PrimitiveSignature> + Send + Sync>,
    /// P256 signer used for estimating fees with p256 key types.
    pub p256_signer: p256::ecdsa::SigningKey,
}

impl fmt::Debug for DynSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RelaySigner").field(&self.address()).finish()
    }
}

impl DynSigner {
    /// Load a private key or AWS signer from environment variables, alongside a P256 key for fee
    /// estimation simulations.
    pub async fn load(key: &str, p256_key: &str, chain_id: Option<u64>) -> eyre::Result<Self> {
        let tx_signer: Arc<dyn FullSigner<PrimitiveSignature> + Send + Sync> =
            if let Ok(wallet) = PrivateKeySigner::from_str(key) {
                Arc::new(wallet)
            } else {
                let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
                let client = aws_sdk_kms::Client::new(&config);
                Arc::new(AwsSigner::new(client, key.to_string(), chain_id).await?)
            };

        let p256_signer =
            p256::ecdsa::SigningKey::from_slice(&hex::decode_to_array::<_, 32>(p256_key)?)?;

        Ok(Self { tx_signer, p256_signer })
    }

    /// Encodes and signs the typed data according to [EIP-712].
    ///
    /// [EIP-712]: https://eips.ethereum.org/EIPS/eip-712
    pub async fn sign_typed_data<T: SolStruct + Send + Sync>(
        &self,
        key_type: KeyType,
        payload: &T,
        domain: &Eip712Domain,
    ) -> eyre::Result<Bytes> {
        let hash = payload.eip712_signing_hash(domain);
        Ok(match key_type {
            KeyType::P256 | KeyType::WebAuthnP256 => <p256::ecdsa::SigningKey as PrehashSigner<
                p256::ecdsa::Signature,
            >>::sign_prehash(
                &self.p256_signer, hash.as_slice()
            )
            .map(|signature| signature.normalize_s().unwrap_or(signature))?
            .to_bytes()
            .to_vec()
            .into(),
            KeyType::Secp256k1 => self.tx_signer.sign_hash(&hash).await?.as_bytes().into(),
            KeyType::__Invalid => unreachable!(),
        })
    }

    /// Returns a copy of the Ethereum transaction signer.
    pub fn transaction_signer(&self) -> Arc<dyn FullSigner<PrimitiveSignature> + Send + Sync> {
        self.tx_signer.clone()
    }

    /// Returns the signer's Ethereum Address.
    pub fn address(&self) -> Address {
        TxSigner::address(&self.tx_signer)
    }

    /// Returns the signer's k256 public key in [`Bytes`].
    pub fn p256_public_key(&self) -> Bytes {
        self.p256_signer.verifying_key().to_encoded_point(false).to_bytes()[1..].to_vec().into()
    }
}

impl Deref for DynSigner {
    type Target = dyn FullSigner<PrimitiveSignature> + Send + Sync;

    fn deref(&self) -> &Self::Target {
        self.tx_signer.as_ref()
    }
}
