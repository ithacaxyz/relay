//! Twilio client implementation.

use super::{
    error::TwilioError,
    lookup::LookupResponse,
    verify::{VerificationCheckResponse, VerificationResponse},
};
use eyre::Result;
use reqwest::Client;
use tracing::error;

/// Twilio client for phone verification.
#[derive(Debug, Clone)]
pub struct TwilioClient {
    client: Client,
    account_sid: String,
    auth_token: String,
    verify_service_sid: String,
}

impl TwilioClient {
    /// Create a new Twilio client.
    pub fn new(account_sid: String, auth_token: String, verify_service_sid: String) -> Self {
        Self { client: Client::new(), account_sid, auth_token, verify_service_sid }
    }

    /// Start phone verification.
    pub async fn start_verification(&self, phone_number: &str) -> Result<VerificationResponse> {
        let url = format!(
            "https://verify.twilio.com/v2/Services/{}/Verifications",
            self.verify_service_sid
        );

        let params = [("To", phone_number), ("Channel", "sms")];

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.account_sid, Some(&self.auth_token))
            .form(&params)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let error: TwilioError = response.json().await?;
            Err(error.into())
        }
    }

    /// Check verification code.
    pub async fn check_verification(
        &self,
        phone_number: &str,
        code: &str,
    ) -> Result<VerificationCheckResponse> {
        let url = format!(
            "https://verify.twilio.com/v2/Services/{}/VerificationCheck",
            self.verify_service_sid
        );

        let params = [("To", phone_number), ("Code", code)];

        let response = self
            .client
            .post(&url)
            .basic_auth(&self.account_sid, Some(&self.auth_token))
            .form(&params)
            .send()
            .await?;

        if response.status().is_success() {
            Ok(response.json().await?)
        } else {
            let error: TwilioError = response.json().await?;
            Err(error.into())
        }
    }

    /// Check if phone is allowed (not VoIP).
    pub async fn is_phone_allowed(&self, phone_number: &str) -> Result<bool> {
        let encoded_phone = urlencoding::encode(phone_number);
        let url = format!(
            "https://lookups.twilio.com/v2/PhoneNumbers/{encoded_phone}?Fields=line_type_intelligence"
        );

        let response = self
            .client
            .get(&url)
            .basic_auth(&self.account_sid, Some(&self.auth_token))
            .send()
            .await?;

        if response.status().is_success() {
            let lookup: LookupResponse = response.json().await?;
            if let Some(intel) = lookup.line_type_intelligence {
                Ok(intel.line_type.is_allowed_for_verification())
            } else {
                // If no line type info, allow by default
                error!("No line type intelligence data returned for phone: {}", phone_number);
                Ok(true)
            }
        } else {
            // If lookup fails, allow by default (could be canadian number)
            error!(
                "Twilio Lookup API failed with status {} for phone: {}",
                response.status(),
                phone_number
            );
            Ok(true)
        }
    }
}
