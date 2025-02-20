//! P256 signer type with webauthn capabilities used for gas estimation and testing.

use crate::types::WebAuthnP256;
use alloy::{
    dyn_abi::Eip712Domain,
    primitives::{bytes, Bytes, B256, U256},
    signers::k256::sha2::{Digest, Sha256},
    sol_types::{SolStruct, SolValue},
};
use base64::Engine;
use p256::ecdsa::signature::hazmat::PrehashSigner;
use serde_json::json;
use std::sync::Arc;

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

    /// Returns the signer's p256 public key in [`Bytes`].
    pub fn public_key(&self) -> Bytes {
        self.0.verifying_key().to_encoded_point(false).to_bytes()[1..].to_vec().into()
    }

    /// Signs the digest with the p256 key.
    fn sign(&self, digest: &[u8]) -> eyre::Result<p256::ecdsa::Signature> {
        Ok(self
            .0
            .sign_prehash(digest)
            .map(|s: p256::ecdsa::Signature| s.normalize_s().unwrap_or(s))?)
    }

    /// Returns a signature that the contract can validate.
    fn sign_with_webauthn(&self, digest: B256) -> eyre::Result<Bytes> {
        // ID || UserPresent Flag || SignatureCounter
        let authenticator_data = bytes!(
            """
            4242424242424242424242424242424242424242424242424242424242424242
            01
            000000
            """
        );

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
        let mut hasher = Sha256::new();
        hasher.update(&authenticator_data);
        hasher.update(Sha256::digest(client_data_json.as_bytes()));
        let digest = hasher.finalize();

        // Sign raw data using p256 signing key
        let signature = self.sign(&digest)?;

        let challenge_index =
            U256::from(client_data_json.find("\"challenge\":").expect("should exist"));
        let type_index = U256::from(client_data_json.find("\"type\":").expect("should exist"));

        Ok(WebAuthnP256 {
            authenticatorData: authenticator_data,
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
