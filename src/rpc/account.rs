//! The `account_` namespace.

use alloy::primitives::keccak256;
use async_trait::async_trait;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use rand::{Rng, distr::Alphanumeric};
use resend_rs::{Resend, types::CreateEmailBaseOptions};
use tracing::info;
use url::Url;

use crate::{
    error::{EmailError, PhoneError},
    rpc::{Relay, RelayApiServer},
    storage::{RelayStorage, StorageApi},
    twilio::TwilioClient,
    types::rpc::{
        ResendVerifyPhoneParameters, SetEmailParameters, SetPhoneParameters, VerifyEmailParameters,
        VerifyPhoneParameters, VerifySignatureParameters,
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

    /// Set the phone number for an account.
    ///
    /// Initiates phone verification via Twilio Verify service.
    /// If the phone already exists in the database and is verified, this returns an error.
    /// If the phone already exists but is not verified, a new verification is initiated.
    #[method(name = "setPhone")]
    async fn set_phone(&self, params: SetPhoneParameters) -> RpcResult<()>;

    /// Verify the phone number for an account using the verification code.
    ///
    /// No signature is required as verification is handled by Twilio.
    #[method(name = "verifyPhone")]
    async fn verify_phone(&self, params: VerifyPhoneParameters) -> RpcResult<()>;

    /// Resend the verification code to a phone number.
    ///
    /// Can be called when the user didn't receive the code or it expired.
    #[method(name = "resendVerifyPhone")]
    async fn resend_verify_phone(&self, params: ResendVerifyPhoneParameters) -> RpcResult<()>;
}

/// Ithaca `account_` RPC module.
#[derive(Debug)]
pub struct AccountRpc {
    relay: Relay,
    client: Resend,
    storage: RelayStorage,
    porto_base_url: String,
    twilio_client: Option<TwilioClient>,
    phone_config: Option<crate::config::PhoneConfig>,
}

impl AccountRpc {
    /// Create a new account RPC module.
    pub fn new(
        relay: Relay,
        client: Resend,
        storage: RelayStorage,
        porto_base_url: String,
    ) -> Self {
        Self { relay, client, storage, porto_base_url, twilio_client: None, phone_config: None }
    }

    /// Create a new account RPC module with phone verification support.
    pub fn with_phone(
        relay: Relay,
        client: Resend,
        storage: RelayStorage,
        porto_base_url: String,
        twilio_client: TwilioClient,
        phone_config: crate::config::PhoneConfig,
    ) -> Self {
        Self {
            relay,
            client,
            storage,
            porto_base_url,
            twilio_client: Some(twilio_client),
            phone_config: Some(phone_config),
        }
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

    async fn set_phone(
        &self,
        SetPhoneParameters { phone, wallet_address }: SetPhoneParameters,
    ) -> RpcResult<()> {
        info!("got setPhone");
        let client = self.twilio_client.as_ref().ok_or_else(|| {
            PhoneError::InternalError(eyre::eyre!("Phone verification not configured"))
        })?;

        // Check if phone is already verified
        if self.storage.verified_phone_exists(&phone).await? {
            return Err(PhoneError::PhoneAlreadyVerified.into());
        }

        info!("checking if phone allowed");
        // Check line type to prevent VoIP numbers
        if !client.is_phone_allowed(&phone).await.map_err(|err| PhoneError::InternalError(err))? {
            return Err(PhoneError::InvalidPhoneNumber.into());
        }

        // Start verification with Twilio Verify API v2
        let verification = client
            .start_verification(&phone)
            .await
            .map_err(|err| PhoneError::InternalError(err))?;

        // Store verification SID in database
        self.storage.add_unverified_phone(wallet_address, &phone, &verification.sid).await?;

        Ok(())
    }

    async fn verify_phone(
        &self,
        VerifyPhoneParameters { phone, code, wallet_address }: VerifyPhoneParameters,
    ) -> RpcResult<()> {
        let client = self.twilio_client.as_ref().ok_or_else(|| {
            PhoneError::InternalError(eyre::eyre!("Phone verification not configured"))
        })?;

        let phone_config = self
            .phone_config
            .as_ref()
            .ok_or_else(|| PhoneError::InternalError(eyre::eyre!("Phone configuration missing")))?;

        // Check attempts
        let attempts = self.storage.get_phone_verification_attempts(wallet_address, &phone).await?;
        if attempts >= phone_config.max_attempts {
            return Err(PhoneError::TooManyAttempts.into());
        }

        // Check verification with Twilio
        let check = client
            .check_verification(&phone, &code)
            .await
            .map_err(|err| PhoneError::InternalError(err))?;

        if !check.status.is_approved() {
            // Increment attempts on failed verification
            self.storage.increment_phone_verification_attempts(wallet_address, &phone).await?;
            return Err(PhoneError::InvalidCode.into());
        }

        // Mark as verified in our database
        self.storage.verify_phone(wallet_address, &phone).await?;

        Ok(())
    }

    async fn resend_verify_phone(
        &self,
        ResendVerifyPhoneParameters { phone, wallet_address }: ResendVerifyPhoneParameters,
    ) -> RpcResult<()> {
        let client = self.twilio_client.as_ref().ok_or_else(|| {
            PhoneError::InternalError(eyre::eyre!("Phone verification not configured"))
        })?;

        // Check if phone is already verified
        if self.storage.verified_phone_exists(&phone).await? {
            return Err(PhoneError::PhoneAlreadyVerified.into());
        }

        // Start a new verification with Twilio
        let verification = client
            .start_verification(&phone)
            .await
            .map_err(|err| PhoneError::InternalError(err))?;

        // Update verification SID in database
        self.storage
            .update_phone_verification_sid(wallet_address, &phone, &verification.sid)
            .await?;

        Ok(())
    }
}

/// Generate a random alphanumeric token.
fn generate_token(length: usize) -> String {
    rand::rng().sample_iter(&Alphanumeric).take(length).map(char::from).collect()
}
