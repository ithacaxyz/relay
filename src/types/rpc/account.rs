//! RPC account-related request and response types.

use super::{AuthorizeKey, AuthorizeKeyResponse, SendPreparedCallsResponse};
use crate::{
    error::{AuthError, KeysError},
    types::{Key, KeyHashWithID, PREPAccount, SignedQuote},
};
use alloy::{
    eips::eip7702::SignedAuthorization,
    primitives::{Address, B256, ChainId, PrimitiveSignature},
};
use jsonrpsee::core::RpcResult;
use serde::{Deserialize, Serialize};

/// Capabilities for `wallet_prepareCreateAccount` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCreateAccountCapabilities {
    /// Keys to authorize on the account.
    pub authorize_keys: Vec<AuthorizeKey>,
    /// Contract address to delegate to.
    pub delegation: Address,
}

impl PrepareCreateAccountCapabilities {
    /// Turns into [PrepareCreateAccountResponseCapabilities]
    pub fn into_response(self) -> PrepareCreateAccountResponseCapabilities {
        PrepareCreateAccountResponseCapabilities {
            authorize_keys: self
                .authorize_keys
                .into_iter()
                .map(|key| key.into_response())
                .collect::<Vec<_>>(),
            delegation: self.delegation,
        }
    }
}

/// Capabilities for `wallet_prepareCreateAccount` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCreateAccountResponseCapabilities {
    /// Keys that were authorized on the account.
    pub authorize_keys: Vec<AuthorizeKeyResponse>,
    /// Contract address the account was delegated to.
    pub delegation: Address,
}

/// Request parameters for `wallet_prepareCreateAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCreateAccountParameters {
    /// Capabilities.
    pub capabilities: PrepareCreateAccountCapabilities,
    /// Chain ID to initialize the account on.
    #[serde(with = "alloy::serde::quantity")]
    pub chain_id: ChainId,
}

/// Response for `wallet_prepareCreateAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareCreateAccountResponse {
    /// Initializable account.
    pub context: CreateAccountContext,
    /// Address of the PREPAccount.
    pub address: Address,
    /// Digests that need to be signed by each admin key identifier.
    pub digests: Vec<B256>,
    /// Capabilities.
    pub capabilities: PrepareCreateAccountResponseCapabilities,
}

/// Request parameters for `wallet_createAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountContext {
    /// Initializable account.
    pub account: PREPAccount,
    /// Chain ID to initialize the account on.
    #[serde(with = "alloy::serde::quantity")]
    pub chain_id: ChainId,
}

/// Request context for `wallet_createAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountParameters {
    /// Initializable account.
    pub context: CreateAccountContext,
    /// List of signatures over the PREPAddress.
    pub signatures: Vec<KeyHashWithID>,
}

impl CreateAccountParameters {
    /// Validates the PREPAccount and key identifier signatures.
    pub fn validate(&self) -> RpcResult<()> {
        // Ensure PREPAccount is well built, since it might not come from the relay.
        if !self.context.account.is_valid() {
            return Err(AuthError::InvalidPrep(self.context.account.clone()).into());
        }

        // Ensure that every key identifier signature is valid and recovers the same id.
        self.validate_signatures()
    }

    /// Verifies all signatures against the [`PREPAccount`] address and key identifiers.
    pub fn validate_signatures(&self) -> RpcResult<()> {
        if self.signatures.is_empty() {
            return Err(KeysError::MissingAdminKey.into());
        }

        for KeyHashWithID { hash, id, signature } in &self.signatures {
            let digest = Key::id_digest_from_hash(*hash, self.context.account.address);
            let expected = signature
                .recover_address_from_prehash(&digest)
                .map_err(|_| KeysError::InvalidKeyIdSignature(*signature))?;

            if *id != expected {
                return Err(KeysError::UnexpectedKeyId { expected, got: *id }.into());
            }
        }
        Ok(())
    }
}

/// Capabilities for `wallet_createAccount` request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpgradeAccountCapabilities {
    /// Keys to authorize on the account.
    pub authorize_keys: Vec<AuthorizeKey>,
    /// Contract address to delegate to.
    pub delegation: Address,
    /// ERC20 token to pay for the gas of the calls.
    ///
    /// Defaults to the native token.
    #[serde(default)]
    pub fee_token: Address,
}

/// Request parameters for `wallet_prepareUpgradeAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PrepareUpgradeAccountParameters {
    /// Address of the EOA to upgrade.
    pub address: Address,
    /// Chain ID to initialize the account on.
    #[serde(with = "alloy::serde::quantity")]
    pub chain_id: ChainId,
    /// Capabilities.
    pub capabilities: UpgradeAccountCapabilities,
}

/// Request parameters for `wallet_upgradeAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeAccountParameters {
    /// The [`SignedQuote`] of the prepared call bundle.
    pub context: SignedQuote,
    /// Signature of the `wallet_prepareUpgradeAccount` digest.
    #[serde(with = "crate::serde::signature")]
    pub signature: PrimitiveSignature,
    /// Signed authorization.
    pub authorization: SignedAuthorization,
}

/// Response for `wallet_upgradeAccount`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpgradeAccountResponse {
    /// Call bundles that were executed.
    pub bundles: Vec<SendPreparedCallsResponse>,
}

/// Request parameters for `wallet_getAccounts`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetAccountsParameters {
    /// Key identifier.
    pub id: Address,
    /// Chain ID.
    pub chain_id: ChainId,
}

/// A response item from `wallet_getAccounts`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountResponse {
    /// Address of the account.
    pub address: Address,
    /// Authorized keys belonging to the account.
    pub keys: Vec<AuthorizeKeyResponse>,
}
