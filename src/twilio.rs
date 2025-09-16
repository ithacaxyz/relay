//! Simple Twilio Verify API v2 and Lookup v2 client implementation.

use reqwest::Client;
use serde::Deserialize;
use std::collections::HashMap;

/// Twilio client for Verify API v2.
#[derive(Clone, Debug)]
pub struct TwilioClient {
    http_client: Client,
    account_sid: String,
    auth_token: String,
    verify_service_sid: String,
}

/// Response from creating a verification.
#[derive(Debug, Deserialize)]
pub struct VerificationResponse {
    /// Unique identifier for this verification.
    pub sid: String,
    /// Status of the verification (e.g., "pending", "approved").
    pub status: String,
    /// The phone number being verified.
    pub to: String,
    /// The channel used for verification (e.g., "sms", "call").
    pub channel: String,
    /// Whether the verification is valid.
    pub valid: bool,
}

/// Response from checking a verification.
#[derive(Debug, Deserialize)]
pub struct VerificationCheckResponse {
    /// Unique identifier for this verification check.
    pub sid: String,
    /// Status of the verification check (e.g., "approved", "pending").
    pub status: String,
    /// The phone number that was verified.
    pub to: String,
    /// The channel used for verification (e.g., "sms", "call").
    pub channel: String,
    /// Whether the verification check was valid.
    pub valid: bool,
}

/// Line type information from Lookup v2 API.
#[derive(Debug, Deserialize)]
pub struct LineTypeIntelligence {
    /// Name of the carrier for this phone number.
    pub carrier_name: Option<String>,
    /// Error code if line type lookup failed.
    pub error_code: Option<String>,
    /// Type of phone line: "mobile", "landline", "voip", or "unknown".
    #[serde(rename = "type")]
    pub line_type: Option<String>,
    /// Mobile country code for the number.
    pub mobile_country_code: Option<String>,
    /// Mobile network code for the number.
    pub mobile_network_code: Option<String>,
}

/// Response from Twilio Lookup v2 API.
#[derive(Debug, Deserialize)]
pub struct LookupResponse {
    /// The phone number in E.164 format.
    pub phone_number: String,
    /// ISO country code for the phone number.
    pub country_code: String,
    /// Phone number formatted for national dialing.
    pub national_format: String,
    /// Whether the phone number is valid.
    pub valid: bool,
    /// Line type intelligence data if requested.
    pub line_type_intelligence: Option<LineTypeIntelligence>,
    /// Country calling code for the number.
    pub calling_country_code: Option<String>,
    /// API URL for this phone number resource.
    pub url: String,
}

/// Twilio error response structure.
#[derive(Debug, Deserialize)]
struct TwilioError {
    code: u32,
    message: String,
}

impl TwilioClient {
    /// Create a new Twilio client.
    pub fn new(account_sid: String, auth_token: String, verify_service_sid: String) -> Self {
        Self { http_client: Client::new(), account_sid, auth_token, verify_service_sid }
    }

    /// Start a verification by sending a code to a phone number.
    pub async fn start_verification(
        &self,
        phone_number: &str,
        channel: &str,
    ) -> eyre::Result<VerificationResponse> {
        let url = format!(
            "https://verify.twilio.com/v2/Services/{}/Verifications",
            self.verify_service_sid
        );

        let mut params = HashMap::new();
        params.insert("To", phone_number);
        params.insert("Channel", channel);

        // Enable line type intelligence for filtering
        params.insert("SendDigits", "3"); // Wait 3 seconds before sending code
        params.insert("Locale", "en");

        let response = self
            .http_client
            .post(&url)
            .basic_auth(&self.account_sid, Some(&self.auth_token))
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await?;

            // Try to parse Twilio error
            if let Ok(twilio_error) = serde_json::from_str::<TwilioError>(&text) {
                return Err(eyre::eyre!("Phone verification failed: {}", twilio_error.message));
            }

            // Generic error if we can't parse the Twilio error
            return Err(eyre::eyre!(
                "Phone verification service error (status: {})",
                status.as_u16()
            ));
        }

        Ok(response.json().await?)
    }

    /// Check a verification code.
    pub async fn check_verification(
        &self,
        phone_number: &str,
        code: &str,
    ) -> eyre::Result<VerificationCheckResponse> {
        let url = format!(
            "https://verify.twilio.com/v2/Services/{}/VerificationCheck",
            self.verify_service_sid
        );

        let mut params = HashMap::new();
        params.insert("To", phone_number);
        params.insert("Code", code);

        let response = self
            .http_client
            .post(&url)
            .basic_auth(&self.account_sid, Some(&self.auth_token))
            .form(&params)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await?;

            // Try to parse Twilio error
            if let Ok(twilio_error) = serde_json::from_str::<TwilioError>(&text) {
                // Handle specific error codes
                match twilio_error.code {
                    20404 => {
                        // Verification expired or already used - treat as invalid code
                        return Err(eyre::eyre!("Invalid or expired verification code"));
                    }
                    20003 => {
                        return Err(eyre::eyre!("Authentication failed"));
                    }
                    20008 => {
                        return Err(eyre::eyre!("Resource not found"));
                    }
                    60200 => {
                        return Err(eyre::eyre!("Invalid verification code"));
                    }
                    60202 => {
                        return Err(eyre::eyre!("Too many verification attempts"));
                    }
                    60203 => {
                        return Err(eyre::eyre!("Too many verification codes sent"));
                    }
                    _ => {
                        // Generic message for other errors
                        return Err(eyre::eyre!("Verification failed"));
                    }
                }
            }

            // Generic error if we can't parse the Twilio error
            return Err(eyre::eyre!("Verification service error (status: {})", status.as_u16()));
        }

        Ok(response.json().await?)
    }

    /// Lookup a phone number and get line type intelligence.
    pub async fn lookup_phone(&self, phone_number: &str) -> eyre::Result<LookupResponse> {
        // URL encode the phone number
        let encoded_phone = urlencoding::encode(phone_number);
        let url = format!("https://lookups.twilio.com/v2/PhoneNumbers/{}", encoded_phone);

        let response = self
            .http_client
            .get(&url)
            .basic_auth(&self.account_sid, Some(&self.auth_token))
            .query(&[("Fields", "line_type_intelligence")])
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let text = response.text().await?;

            // Try to parse Twilio error
            if let Ok(twilio_error) = serde_json::from_str::<TwilioError>(&text) {
                return Err(eyre::eyre!("Phone lookup failed: {}", twilio_error.message));
            }

            // Generic error if we can't parse the Twilio error
            return Err(eyre::eyre!("Phone lookup service error (status: {})", status.as_u16()));
        }

        Ok(response.json().await?)
    }

    /// Check if a phone number is allowed for verification (not VoIP).
    pub async fn is_phone_allowed(&self, phone_number: &str) -> eyre::Result<bool> {
        let lookup = self.lookup_phone(phone_number).await?;

        // Check if the phone number is valid
        if !lookup.valid {
            return Ok(false);
        }

        // Check line type - deny VoIP, allow everything else
        if let Some(line_type_intel) = lookup.line_type_intelligence {
            // If line type is explicitly VoIP, deny it
            if line_type_intel.line_type.as_deref() == Some("voip") {
                Ok(false)
            } else {
                // Allow mobile, landline, and even unknown (since many legitimate numbers show as
                // unknown)
                Ok(true)
            }
        } else {
            // If we can't get line type intelligence, allow it (don't block legitimate users)
            Ok(true)
        }
    }
}
