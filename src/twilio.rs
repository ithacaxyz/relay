//! Simple Twilio Verify API v2 and Lookup v2 client implementation.

use reqwest::Client;
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;
use tracing::{error, info};

/// Twilio client for Verify API v2.
#[derive(Clone, Debug)]
pub struct TwilioClient {
    http_client: Client,
    account_sid: String,
    auth_token: String,
    verify_service_sid: String,
}

/// Verification status from Twilio Verify API.
///
/// See [Twilio Verification Check API documentation](https://www.twilio.com/docs/verify/api/verification-check)
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VerificationStatus {
    /// Verification is pending (code sent, awaiting user input)
    Pending,
    /// Verification is approved (correct code provided)
    Approved,
    /// Verification was canceled
    Canceled,
    /// Maximum attempts exceeded
    #[serde(rename = "max_attempts_reached")]
    MaxAttemptsReached,
    /// Verification has been deleted
    Deleted,
    /// Verification failed
    Failed,
    /// Verification has expired
    Expired,
}

impl VerificationStatus {
    /// Check if the verification is approved.
    pub fn is_approved(&self) -> bool {
        matches!(self, Self::Approved)
    }

    /// Check if the verification is still pending.
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Check if the verification failed or was invalid.
    pub fn is_failed(&self) -> bool {
        matches!(
            self,
            Self::Failed
                | Self::Expired
                | Self::MaxAttemptsReached
                | Self::Canceled
                | Self::Deleted
        )
    }
}

/// Response from creating a verification.
#[derive(Debug, Deserialize)]
pub struct VerificationResponse {
    /// Unique identifier for this verification.
    pub sid: String,
    /// Status of the verification.
    pub status: VerificationStatus,
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
    /// Status of the verification check.
    pub status: VerificationStatus,
    /// The phone number that was verified.
    pub to: String,
    /// The channel used for verification (e.g., "sms", "call").
    pub channel: String,
    /// Whether the verification check was valid.
    pub valid: bool,
}

/// Phone line type from Twilio Lookup v2 API.
///
/// See [Twilio's Line Type Intelligence documentation](https://www.twilio.com/docs/lookup/v2-api/line-type-intelligence#type-property-values)
/// for detailed descriptions of each type.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LineType {
    /// Mobile phone line
    Mobile,
    /// Landline phone
    Landline,
    /// Voice over IP line
    Voip,
    /// Fixed VoIP (non-mobile VoIP with fixed address)
    #[serde(rename = "fixedVoip")]
    FixedVoip,
    /// Non-fixed VoIP (can be used from anywhere)
    #[serde(rename = "nonFixedVoip")]
    NonFixedVoip,
    /// Toll-free number
    Tollfree,
    /// Premium rate number
    Premium,
    /// Shared cost number
    #[serde(rename = "sharedCost")]
    SharedCost,
    /// Universal Access Number
    Uan,
    /// Voicemail service
    Voicemail,
    /// Pager service
    Pager,
    /// Unknown or unidentified line type
    Unknown,
}

impl LineType {
    /// Check if this line type is VoIP (including all VoIP variants).
    pub fn is_voip(&self) -> bool {
        matches!(self, LineType::Voip | LineType::FixedVoip | LineType::NonFixedVoip)
    }

    /// Check if this line type should be allowed for verification.
    /// We allow mobile and landline, but block VoIP and special services.
    pub fn is_allowed_for_verification(&self) -> bool {
        matches!(self, LineType::Mobile | LineType::Landline)
    }
}

/// Line type information from Lookup v2 API.
#[derive(Debug, Deserialize)]
pub struct LineTypeIntelligence {
    /// Name of the carrier for this phone number.
    pub carrier_name: Option<String>,
    /// Error code if line type lookup failed.
    pub error_code: Option<String>,
    /// Type of phone line.
    #[serde(rename = "type")]
    pub line_type: Option<LineType>,
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

/// Known Twilio error codes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TwilioErrorCode {
    /// Authentication failed (20003)
    AuthenticationFailed,
    /// Resource not found (20008)
    ResourceNotFound,
    /// Verification expired or already used (20404)
    VerificationExpired,
    /// Invalid verification code (60200)
    InvalidVerificationCode,
    /// Too many verification attempts (60202)
    TooManyAttempts,
    /// Too many verification codes sent (60203)
    TooManyCodesSent,
    /// Unknown error code
    Unknown(u32),
}

impl TwilioErrorCode {
    /// Get a user-friendly error message for this error code.
    pub fn user_message(&self) -> &'static str {
        match self {
            Self::AuthenticationFailed => "Authentication failed",
            Self::ResourceNotFound => "Resource not found",
            Self::VerificationExpired => "Invalid or expired verification code",
            Self::InvalidVerificationCode => "Invalid verification code",
            Self::TooManyAttempts => "Too many verification attempts",
            Self::TooManyCodesSent => "Too many verification codes sent",
            Self::Unknown(_) => "Verification failed",
        }
    }
}

impl<'de> Deserialize<'de> for TwilioErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let code = u32::deserialize(deserializer)?;
        Ok(match code {
            20003 => Self::AuthenticationFailed,
            20008 => Self::ResourceNotFound,
            20404 => Self::VerificationExpired,
            60200 => Self::InvalidVerificationCode,
            60202 => Self::TooManyAttempts,
            60203 => Self::TooManyCodesSent,
            code => Self::Unknown(code),
        })
    }
}

/// Twilio error response structure.
#[derive(Debug, Deserialize)]
struct TwilioError {
    code: TwilioErrorCode,
    message: String,
}

impl TwilioError {
    /// Parse error response and return appropriate error.
    fn parse_error(text: &str) -> Option<String> {
        if let Ok(twilio_error) = serde_json::from_str::<TwilioError>(text) {
            // Log the full error details if it's an unknown error
            if let TwilioErrorCode::Unknown(code) = &twilio_error.code {
                error!("Unknown Twilio error code {}: {}", code, twilio_error.message);
            }
            Some(twilio_error.code.user_message().to_string())
        } else {
            None
        }
    }
}

impl TwilioClient {
    /// Create a new Twilio client.
    pub fn new(account_sid: String, auth_token: String, verify_service_sid: String) -> Self {
        Self { http_client: Client::new(), account_sid, auth_token, verify_service_sid }
    }

    /// Start a verification by sending an SMS code to a phone number.
    pub async fn start_verification(
        &self,
        phone_number: &str,
    ) -> eyre::Result<VerificationResponse> {
        let url = format!(
            "https://verify.twilio.com/v2/Services/{}/Verifications",
            self.verify_service_sid
        );

        let mut params = HashMap::new();
        params.insert("To", phone_number);
        params.insert("Channel", "sms");

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
            let error_msg = TwilioError::parse_error(&text).unwrap_or_else(|| {
                format!("Phone verification service error (status: {})", status.as_u16())
            });
            return Err(eyre::eyre!("{}", error_msg));
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
            let error_msg = TwilioError::parse_error(&text).unwrap_or_else(|| {
                format!("Verification service error (status: {})", status.as_u16())
            });
            return Err(eyre::eyre!("{}", error_msg));
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
            let error_msg = TwilioError::parse_error(&text).unwrap_or_else(|| {
                format!("Phone lookup service error (status: {})", status.as_u16())
            });
            return Err(eyre::eyre!("{}", error_msg));
        }

        Ok(response.json().await?)
    }

    /// Check if a phone number is allowed for verification (not VoIP).
    pub async fn is_phone_allowed(&self, phone_number: &str) -> eyre::Result<bool> {
        info!("Checking if phone is allowed: {phone_number}");
        let lookup = self.lookup_phone(phone_number).await?;
        info!("Lookup result: {lookup:?}");

        // Check if the phone number is valid
        if !lookup.valid {
            info!("Phone number is invalid");
            return Ok(false);
        }

        // Check line type intelligence
        if let Some(line_type_intel) = lookup.line_type_intelligence {
            if let Some(line_type) = line_type_intel.line_type {
                info!(
                    "Line type: {:?}, is_voip: {}, allowed: {}",
                    line_type,
                    line_type.is_voip(),
                    line_type.is_allowed_for_verification()
                );

                // Use the enum's method to check if allowed
                Ok(line_type.is_allowed_for_verification())
            } else {
                // No line type information available - be conservative and allow
                info!("No line type information available, allowing");
                Ok(true)
            }
        } else {
            // If we can't get line type intelligence, allow it (don't block legitimate users)
            info!("No line type intelligence available, allowing");
            Ok(true)
        }
    }
}
