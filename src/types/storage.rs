use super::{SignedCall, rpc::AuthorizeKeyResponse};
use crate::error::RelayError;
use alloy::{
    eips::eip7702::SignedAuthorization,
    primitives::{Address, Bytes},
    rpc::types::state::{AccountOverride, StateOverride, StateOverridesBuilder},
    sol_types::SolValue,
};
use serde::{Deserialize, Serialize};

/// CreateAccount request that can be reused across chains.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatableAccount {
    /// EOA generated address.
    pub address: Address,
    /// Signed 7702 authorization.
    pub signed_authorization: SignedAuthorization,
    /// Initialization calls.
    pub pre_call: SignedCall,
}

impl CreatableAccount {
    /// Initializes a new account.
    pub fn new(
        eoa: Address,
        pre_call: SignedCall,
        signed_authorization: SignedAuthorization,
    ) -> Self {
        Self { address: eoa, signed_authorization, pre_call }
    }

    /// Return abi encoded precall.
    pub fn init_data(&self) -> Bytes {
        self.pre_call.abi_encode_params().into()
    }

    /// Return the list of authorized keys as [`AuthorizeKeyResponse`].
    pub fn authorized_keys(&self) -> Result<Vec<AuthorizeKeyResponse>, RelayError> {
        Ok(self.pre_call.authorized_keys_with_permissions()?)
    }

    /// Builds state overrides for the account, including 7702 authorization and authorized keys.
    pub fn state_overrides(&self) -> Result<StateOverride, RelayError> {
        Ok(StateOverridesBuilder::with_capacity(1)
            .append(
                self.address,
                AccountOverride::default()
                    .with_7702_delegation_designator(self.signed_authorization.address)
                    .with_state_diff(
                        self.authorized_keys()?
                            .into_iter()
                            .flat_map(|k| k.authorize_key.key.storage_slots().into_iter()),
                    ),
            )
            .build())
    }
}
