use super::{p256::P256Key, Eip712PayLoadSigner};
use crate::types::WebAuthnP256;
use alloy::{
    primitives::{bytes, Bytes, B256, U256},
    signers::k256::sha2::{Digest, Sha256},
    sol_types::SolValue,
};
use base64::Engine;
use p256::ecdsa::SigningKey;
use serde_json::json;
use std::sync::Arc;

/// Abstraction over a P256 signer with webauthn capabilities.
#[derive(Debug)]
pub struct WebAuthnSigner(pub Arc<SigningKey>);

impl WebAuthnSigner {
    /// Loads a P256 key.
    pub fn load(key: &B256) -> eyre::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self(Arc::new(SigningKey::from_slice(key.as_slice())?)))
    }
}

impl P256Key for WebAuthnSigner {
    fn signing_key(&self) -> &SigningKey {
        &self.0
    }
}

#[async_trait::async_trait]
impl Eip712PayLoadSigner for WebAuthnSigner {
    async fn sign_payload_hash(&self, payload_hash: B256) -> eyre::Result<Bytes> {
        // ID || UserPresent Flag || SignatureCounter
        let authenticator_data = bytes!(
            """
            4242424242424242424242424242424242424242424242424242424242424242
            01
            000000
            """
        );

        // Build clientDataJSON
        let challenge_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload_hash);
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
        let signature = self.sign_prehash(&digest)?;

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
