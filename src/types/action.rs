use alloy::eips::eip7702::SignedAuthorization;
use serde::{Deserialize, Serialize};

use super::{PartialUserOp, UserOp};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartialAction {
    pub op: PartialUserOp,
    pub auth: Option<SignedAuthorization>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub op: UserOp,
    pub auth: Option<SignedAuthorization>,
}
