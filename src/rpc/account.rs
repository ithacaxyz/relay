//! The `account_` namespace.

use alloy::primitives::keccak256;
use async_trait::async_trait;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use rand::{Rng, distr::Alphanumeric};
use resend_rs::{Resend, types::CreateEmailBaseOptions};
use url::Url;

use crate::{
    config::PhoneConfig,
    error::{EmailError, OnrampError, PhoneError},
    rpc::{Relay, RelayApiServer},
    storage::{RelayStorage, StorageApi},
    twilio::TwilioClient,
    types::rpc::{
        GetOnrampContactInfoParameters, GetOnrampContactInfoResponse, OnrampStatusParameters,
        OnrampStatusResponse, ResendVerifyPhoneParameters, SetEmailParameters, SetPhoneParameters,
        VerifyEmailParameters, VerifyPhoneParameters, VerifySignatureParameters,
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
    /// The phone starts out unverified, and can later be verified with [`verify_phone`].
    ///
    /// This initiates phone verification by sending an SMS with a verification code via Twilio
    /// Verify service.
    ///
    /// If the phone already exists in the database and is verified, this returns an error.
    ///
    /// If the phone already exists in the database but is not verified, a new verification is
    /// initiated and a new SMS is sent.
    ///
    /// VoIP numbers are automatically rejected to prevent abuse.
    #[method(name = "setPhone")]
    async fn set_phone(&self, params: SetPhoneParameters) -> RpcResult<()>;

    /// Verify the phone number for an account using the verification code.
    ///
    /// The verification code is the 6-digit code sent via SMS to the phone number.
    ///
    /// Unlike email verification, no signature is required as the possession of the SMS code
    /// proves ownership of the phone number.
    ///
    /// Returns an error if:
    /// - The verification code is invalid or expired
    /// - Too many failed attempts have been made (limit configured in PhoneConfig)
    /// - The phone number is not pending verification
    #[method(name = "verifyPhone")]
    async fn verify_phone(&self, params: VerifyPhoneParameters) -> RpcResult<()>;

    /// Resend the verification code to a phone number.
    ///
    /// Can be called when the user didn't receive the code or it expired. This will send a new
    /// SMS with a new verification code.
    ///
    /// Returns an error if the phone is already verified.
    ///
    /// The previous verification session is invalidated and a new one is created.
    #[method(name = "resendVerifyPhone")]
    async fn resend_verify_phone(&self, params: ResendVerifyPhoneParameters) -> RpcResult<()>;

    /// Get onramp verification status for an account.
    ///
    /// Returns Unix timestamps (seconds) for when email and phone were verified.
    /// Returns null for unverified contact methods.
    ///
    /// This method does not return actual email or phone values to prevent enumeration attacks.
    #[method(name = "onrampStatus")]
    async fn onramp_status(
        &self,
        params: OnrampStatusParameters,
    ) -> RpcResult<OnrampStatusResponse>;

    /// Get verified contact information for onramp.
    /// Requires authentication via secret.
    #[method(name = "getOnrampContactInfo")]
    async fn get_onramp_contact_info(
        &self,
        params: GetOnrampContactInfoParameters,
    ) -> RpcResult<GetOnrampContactInfoResponse>;
}

/// Ithaca `account_` RPC module.
#[derive(Debug)]
pub struct AccountRpc {
    relay: Relay,
    client: Resend,
    storage: RelayStorage,
    porto_base_url: String,
    twilio_client: Option<TwilioClient>,
    phone_config: Option<PhoneConfig>,
    onramp_worker_secret: String,
}

impl AccountRpc {
    /// Create a new account RPC module.
    pub fn new(
        relay: Relay,
        client: Resend,
        storage: RelayStorage,
        porto_base_url: String,
        onramp_worker_secret: String,
    ) -> Self {
        Self {
            relay,
            client,
            storage,
            porto_base_url,
            twilio_client: None,
            phone_config: None,
            onramp_worker_secret,
        }
    }

    /// Create a new account RPC module with phone verification support.
    pub fn with_phone(
        relay: Relay,
        client: Resend,
        storage: RelayStorage,
        porto_base_url: String,
        twilio_client: TwilioClient,
        phone_config: PhoneConfig,
        onramp_worker_secret: String,
    ) -> Self {
        Self {
            relay,
            client,
            storage,
            porto_base_url,
            twilio_client: Some(twilio_client),
            phone_config: Some(phone_config),
            onramp_worker_secret,
        }
    }

    /// Ensures there is a twilio client configured, otherwise returns an error.
    pub fn ensure_twilio_client(&self) -> Result<&TwilioClient, PhoneError> {
        self.twilio_client.as_ref().ok_or_else(|| {
            PhoneError::InternalError(eyre::eyre!("Phone verification not configured"))
        })
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
        let client = self.ensure_twilio_client()?;

        // Check if phone is already verified
        if self.storage.verified_phone_exists(&phone).await? {
            return Err(PhoneError::PhoneAlreadyVerified.into());
        }

        // Check line type to prevent VoIP numbers
        if !client.is_phone_allowed(&phone).await.map_err(PhoneError::InternalError)? {
            return Err(PhoneError::InvalidPhoneNumber.into());
        }

        // Start verification with Twilio Verify API v2
        let verification =
            client.start_verification(&phone).await.map_err(PhoneError::InternalError)?;

        // Store verification SID in database
        self.storage.add_unverified_phone(wallet_address, &phone, &verification.sid).await?;

        Ok(())
    }

    async fn verify_phone(
        &self,
        VerifyPhoneParameters { phone, code, wallet_address }: VerifyPhoneParameters,
    ) -> RpcResult<()> {
        let client = self.ensure_twilio_client()?;

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
        let check =
            client.check_verification(&phone, &code).await.map_err(PhoneError::InternalError)?;

        if !check.status.is_approved() {
            // Increment attempts on failed verification
            self.storage.increment_phone_verification_attempts(wallet_address, &phone).await?;
            return Err(PhoneError::InvalidCode.into());
        }

        // Mark as verified in our database
        self.storage.mark_phone_verified(wallet_address, &phone).await?;

        Ok(())
    }

    async fn resend_verify_phone(
        &self,
        ResendVerifyPhoneParameters { phone, wallet_address }: ResendVerifyPhoneParameters,
    ) -> RpcResult<()> {
        let client = self.ensure_twilio_client()?;

        // Check if phone is already verified
        if self.storage.verified_phone_exists(&phone).await? {
            return Err(PhoneError::PhoneAlreadyVerified.into());
        }

        // Start a new verification with Twilio
        let verification =
            client.start_verification(&phone).await.map_err(PhoneError::InternalError)?;

        // Update verification SID in database
        self.storage
            .update_phone_verification_sid(wallet_address, &phone, &verification.sid)
            .await?;

        Ok(())
    }

    async fn onramp_status(
        &self,
        params: OnrampStatusParameters,
    ) -> RpcResult<OnrampStatusResponse> {
        let status = self.storage.get_onramp_verification_status(params.address).await?;

        Ok(OnrampStatusResponse { email: status.email, phone: status.phone })
    }

    async fn get_onramp_contact_info(
        &self,
        params: GetOnrampContactInfoParameters,
    ) -> RpcResult<GetOnrampContactInfoResponse> {
        if params.secret != self.onramp_worker_secret {
            return Err(OnrampError::InvalidSecret.into());
        }

        let contact_info = self.storage.get_onramp_contact_info(params.address).await?;

        Ok(GetOnrampContactInfoResponse { email: contact_info.email, phone: contact_info.phone })
    }
}

/// Generate a random alphanumeric token.
fn generate_token(length: usize) -> String {
    rand::rng().sample_iter(&Alphanumeric).take(length).map(char::from).collect()
}
