//! The `account_` namespace.

use alloy::primitives::keccak256;
use async_trait::async_trait;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use rand::{Rng, distr::Alphanumeric};
use resend_rs::{Resend, types::CreateEmailBaseOptions};
use url::Url;

use crate::{
    error::EmailError,
    rpc::{Relay, RelayApiServer},
    storage::{RelayStorage, StorageApi},
    types::rpc::{
        CheckEmailVerifiedParameters, CheckEmailVerifiedResponse, SetEmailParameters,
        VerifyEmailParameters, VerifySignatureParameters,
    },
};

/// Ithaca `account_` RPC namespace.
#[rpc(server, client, namespace = "account")]
pub trait AccountApi {
    /// Set the email address for an account.
    ///
    /// The email starts out unverified, and can later be verified with [`verify_email`].
    ///
    /// If the account already has an email address, it will be replaced with the new one once it is
    /// verified.
    ///
    /// If the email already exists in the database and is verified, this returns an error.
    ///
    /// If the email already exists in the database, but is not verified, a new token is generated
    /// and a new verification email is sent.
    #[method(name = "setEmail")]
    async fn set_email(&self, params: SetEmailParameters) -> RpcResult<()>;

    /// Verify the email address for an account using a signed verification code.
    ///
    /// The verification code is signed to ensure the account owner wanted the email to be added to
    /// the account.
    #[method(name = "verifyEmail")]
    async fn verify_email(&self, params: VerifyEmailParameters) -> RpcResult<()>;

    /// Check if an email is verified for a given wallet address.
    ///
    /// If an email is provided, checks if that specific email is verified for the wallet.
    /// If no email is provided, returns any verified email for the wallet.
    #[method(name = "checkEmailVerified")]
    async fn check_email_verified(
        &self,
        params: CheckEmailVerifiedParameters,
    ) -> RpcResult<CheckEmailVerifiedResponse>;
}

/// Ithaca `account_` RPC module.
#[derive(Debug)]
pub struct AccountRpc {
    relay: Relay,
    client: Resend,
    storage: RelayStorage,
    porto_base_url: String,
}

impl AccountRpc {
    /// Create a new account RPC module.
    pub fn new(
        relay: Relay,
        client: Resend,
        storage: RelayStorage,
        porto_base_url: String,
    ) -> Self {
        Self { relay, client, storage, porto_base_url }
    }
}

#[async_trait]
impl AccountApiServer for AccountRpc {
    async fn set_email(
        &self,
        SetEmailParameters { email, wallet_address }: SetEmailParameters,
    ) -> RpcResult<()> {
        if self.storage.verified_email_exists(&email).await? {
            return Err(EmailError::EmailAlreadyVerified.into());
        }

        let token = generate_token(8);

        let mut url = Url::parse(&format!("https://{}/email/verify", self.porto_base_url)).unwrap();
        url.query_pairs_mut().append_pair("address", wallet_address.to_string().as_str());
        url.query_pairs_mut().append_pair("email", email.as_str());
        url.query_pairs_mut().append_pair("token", token.as_str());

        let mail = CreateEmailBaseOptions::new(
            "Porto <no-reply@porto.sh>",
            &[email.to_string()],
            "Verify email address for Porto",
        )
        .with_text(&format!(
            "Click the following link to verify your email address:\n\n\
            {url}\n\n\
            If you did not create a Porto account, you can safely ignore this."
        ));

        self.client.emails.send(mail).await.map_err(|err| EmailError::InternalError(err.into()))?;

        // generate token
        self.storage.add_unverified_email(wallet_address, &email, &token).await?;

        Ok(())
    }

    async fn verify_email(
        &self,
        VerifyEmailParameters { chain_id, email, wallet_address, token, signature }: VerifyEmailParameters,
    ) -> RpcResult<()> {
        // check the signature
        if !self
            .relay
            .verify_signature(VerifySignatureParameters {
                address: wallet_address,
                digest: keccak256(format!("{email}{token}")),
                signature,
                chain_id,
            })
            .await
            .map_err(|err| EmailError::InternalError(err.into()))?
            .valid
        {
            return Err(EmailError::InvalidSignature.into());
        }

        // check the token
        if !self.storage.verify_email(wallet_address, &email, &token).await? {
            // couldnt verify error
            return Err(EmailError::InvalidToken.into());
        }

        Ok(())
    }

    async fn check_email_verified(
        &self,
        CheckEmailVerifiedParameters { wallet_address, email }: CheckEmailVerifiedParameters,
    ) -> RpcResult<CheckEmailVerifiedResponse> {
        if let Some(specific_email) = email {
            // Check if specific email is verified for this wallet
            let verified_email = self.storage.get_verified_email(wallet_address).await?;
            let verified = verified_email.as_ref() == Some(&specific_email);
            Ok(CheckEmailVerifiedResponse {
                verified,
                email: if verified { Some(specific_email) } else { None },
            })
        } else {
            // Check if any email is verified for this wallet
            let verified_email = self.storage.get_verified_email(wallet_address).await?;
            Ok(CheckEmailVerifiedResponse {
                verified: verified_email.is_some(),
                email: verified_email,
            })
        }
    }
}

/// Generate a random alphanumeric token.
fn generate_token(length: usize) -> String {
    rand::rng().sample_iter(&Alphanumeric).take(length).map(char::from).collect()
}
