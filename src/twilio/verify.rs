//! Twilio Verify API v2 types.

use serde::{Deserialize, Deserializer};

/// Twilio Verify API verification response.
#[derive(Debug, Deserialize)]
pub struct VerificationResponse {
    /// Verification SID.
    pub sid: String,
    /// Verification status.
    pub status: VerificationStatus,
}

/// Twilio Verify API verification check response.
#[derive(Debug, Deserialize)]
pub struct VerificationCheckResponse {
    /// Verification status.
    pub status: VerificationStatus,
}

/// Verification status.
///
/// See <https://www.twilio.com/docs/verify/api/verification-check> for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationStatus {
    /// Verification pending.
    Pending,
    /// Verification approved.
    Approved,
    /// Verification canceled.
    Canceled,
    /// Max attempts reached.
    MaxAttemptsReached,
    /// Verification deleted.
    Deleted,
    /// Verification failed.
    Failed,
    /// Verification expired.
    Expired,
}

impl VerificationStatus {
    /// Check if verification is approved.
    pub fn is_approved(&self) -> bool {
        matches!(self, VerificationStatus::Approved)
    }
}

impl<'de> Deserialize<'de> for VerificationStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "pending" => Self::Pending,
            "approved" => Self::Approved,
            "canceled" => Self::Canceled,
            "max_attempts_reached" => Self::MaxAttemptsReached,
            "deleted" => Self::Deleted,
            "failed" => Self::Failed,
            "expired" => Self::Expired,
            _ => Self::Failed,
        })
    }
}
