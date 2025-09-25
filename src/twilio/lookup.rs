//! Twilio Lookup API v2 types.

use serde::Deserialize;

/// Twilio Lookup v2 response.
#[derive(Debug, Deserialize)]
pub struct LookupResponse {
    /// Phone number information.
    pub line_type_intelligence: Option<LineTypeIntelligence>,
}

/// Line type intelligence data.
#[derive(Debug, Deserialize)]
pub struct LineTypeIntelligence {
    /// Type of phone line.
    #[serde(rename = "type")]
    pub line_type: LineType,
}

/// Phone line type.
///
/// See <https://www.twilio.com/docs/lookup/v2-api/line-type-intelligence> for more details.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LineType {
    /// Mobile phone.
    Mobile,
    /// Landline phone.
    Landline,
    /// VoIP phone.
    Voip,
    /// Fixed VoIP.
    FixedVoip,
    /// Non-fixed VoIP.
    NonFixedVoip,
    /// Pager.
    Pager,
    /// Toll-free number.
    TollFree,
    /// Premium rate number.
    Premium,
    /// Shared cost number.
    SharedCost,
    /// Unknown type.
    Unknown,
}

impl LineType {
    /// Check if this line type is allowed for verification.
    pub fn is_allowed_for_verification(&self) -> bool {
        matches!(self, LineType::Mobile | LineType::Landline)
    }
}
