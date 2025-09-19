//! Twilio error types.

use serde::{Deserialize, Deserializer};
use tracing::error;

/// Twilio error response.
#[derive(Debug, Deserialize)]
pub struct TwilioError {
    /// Error code.
    pub code: TwilioErrorCode,
    /// Error message.
    pub message: String,
    /// More info URL.
    pub more_info: String,
    /// HTTP status code.
    pub status: u16,
}

/// Twilio error codes.
///
/// See <https://www.twilio.com/docs/verify/api> for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum TwilioErrorCode {
    /// Resource not found.
    NotFound = 20404,
    /// Too many requests.
    TooManyRequests = 20429,
    /// Unknown error code.
    Unknown(u32),
}

impl<'de> Deserialize<'de> for TwilioErrorCode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let code = u32::deserialize(deserializer)?;
        Ok(match code {
            20404 => Self::NotFound,
            20429 => Self::TooManyRequests,
            other => Self::Unknown(other),
        })
    }
}

impl From<TwilioError> for eyre::Report {
    fn from(error: TwilioError) -> Self {
        match error.code {
            TwilioErrorCode::NotFound => {
                // 20404 can mean verification was "soft deleted" after too many failed attempts
                eyre::eyre!("Invalid or expired verification code")
            }
            TwilioErrorCode::TooManyRequests => {
                eyre::eyre!("Too many requests, please try again later")
            }
            TwilioErrorCode::Unknown(_) => {
                error!("Unknown Twilio error {error:?}");
                eyre::eyre!("Phone verification service error")
            }
        }
    }
}
