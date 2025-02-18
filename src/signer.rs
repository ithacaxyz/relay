//! Multi-signer abstraction.
//!
//! A signer abstracted over multiple underlying signers, e.g. local or AWS.
use crate::types::WebAuthnP256;
use alloy::{
    dyn_abi::Eip712Domain,
    network::{FullSigner, TxSigner},
    primitives::{Address, Bytes, PrimitiveSignature, B256, U256},
    signers::{
        aws::AwsSigner,
        k256::sha2::{Digest, Sha256},
        local::PrivateKeySigner,
    },
    sol_types::{SolStruct, SolValue},
};
use aws_config::BehaviorVersion;
use base64::Engine;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use serde_json::json;
use std::{fmt, ops::Deref, str::FromStr, sync::Arc};

/// Abstraction over local signer or AWS.
pub struct DynSigner(pub Arc<dyn FullSigner<PrimitiveSignature> + Send + Sync>);

impl fmt::Debug for DynSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RelaySigner").field(&self.address()).finish()
    }
}

impl DynSigner {
    /// Load a private key or AWS signer from environment variables.
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
    ) -> eyre::Result<PrimitiveSignature> {
        Ok(self.sign_hash(&payload.eip712_signing_hash(domain)).await?)
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

/// Abstraction over a P256 signer with webauthn capabilities.
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
        is_webauthn: bool,
    ) -> eyre::Result<Bytes> {
        let digest = payload.eip712_signing_hash(domain);

        if is_webauthn {
            return self.sign_with_webauthn(digest);
        }

        Ok(self.sign(digest.as_slice())?.to_bytes().to_vec().into())
    }

    /// Returns the signer's k256 public key in [`Bytes`].
    pub fn public_key(&self) -> Bytes {
        self.0.verifying_key().to_encoded_point(false).to_bytes()[1..].to_vec().into()
    }

    fn sign(&self, digest: &[u8]) -> eyre::Result<p256::ecdsa::Signature> {
        Ok(self
            .0
            .sign_prehash(digest)
            .map(|s: p256::ecdsa::Signature| s.normalize_s().unwrap_or(s))?)
    }

    /// Returns a signature that the contract can validate.
    fn sign_with_webauthn(&self, digest: B256) -> eyre::Result<Bytes> {
        // Build authenticatorData
        let mut authenticator_data = Vec::new();
        authenticator_data.extend_from_slice(B256::random().as_slice());

        // User Present. User verification is default false, otherwise |= 4
        let flags: u8 = 0x01;
        authenticator_data.push(flags);

        // Signature counter
        authenticator_data.extend_from_slice(&0u32.to_be_bytes());

        // Build clientDataJSON
        let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest);
        let client_data = json!({
            "type": "webauthn.get",
            "challenge": challenge_b64,
            "origin": "https//ithaca.xyz",
            "crossOrigin": false
        });
        let client_data_json = serde_json::to_string(&client_data)?;

        // Build digest: SHA256(authenticatorData || SHA256(clientDataJSON))
        let client_data_hash = Sha256::digest(client_data_json.as_bytes());
        let mut raw = authenticator_data.clone();
        raw.extend_from_slice(&client_data_hash);
        let digest = Sha256::digest(raw);

        // Sign raw data using p256 signing key
        let signature = self.sign(&digest)?;

        let challenge_index =
            U256::from(client_data_json.find("\"challenge\":").expect("should exist"));
        let type_index = U256::from(client_data_json.find("\"type\":").expect("should exist"));

        Ok(WebAuthnP256 {
            authenticatorData: authenticator_data.into(),
            clientDataJSON: client_data_json,
            challengeIndex: challenge_index,
            typeIndex: type_index,
            r: B256::from_slice(signature.r().to_bytes().as_slice()),
            s: B256::from_slice(signature.s().to_bytes().as_slice()),
        }
        .abi_encode()
        .into())
    }
}
