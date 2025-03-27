//! RPC account-related request and response types.

use super::{AuthorizeKey, AuthorizeKeyResponse, KeySignature, SendPreparedCallsResponse};
use crate::{
    error::{AuthError, KeysError},
    types::{Key, KeyHashWithID, KeyID, PREPAccount, SignedQuote, UserOp},
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
    /// List of key id signatures over the PREPAddress.
    pub signatures: Vec<KeySignature>,
}

impl CreateAccountParameters {
    /// Validates [`CreateAccountParameters`] and returns the derived list of [`KeyHashWithID`].
    pub fn validate_and_get_key_ids(&self) -> RpcResult<Vec<KeyHashWithID>> {
        // Ensure PREPAccount is well built, since it might not come from the relay.
        if !self.context.account.is_valid() {
            return Err(AuthError::InvalidPrep(self.context.account.clone()).into());
        }

        if self.signatures.is_empty() {
            return Err(KeysError::MissingAdminKey.into());
        }

        self.key_identifiers()
    }

    /// Validates all signatures and returns the derived list of [`KeyHashWithID`].
    fn key_identifiers(&self) -> RpcResult<Vec<KeyHashWithID>> {
        self.signatures
            .iter()
            .map(|KeySignature { public_key, key_type, value }| {
                let hash = Key::hash(*key_type, public_key);
                let digest = Key::id_digest_from_hash(hash, self.context.account.address);

                PrimitiveSignature::from_raw(value)
                    .and_then(|signature| {
                        signature.recover_address_from_prehash(&digest).map(|id| KeyHashWithID {
                            hash,
                            id,
                            signature,
                        })
                    })
                    .map_err(|_| KeysError::InvalidKeyIdSignature(value.clone()).into())
            })
            .collect()
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
    /// Optional preOps to execute before signature verification.
    ///
    /// See [`UserOp::encodedPreOps`].
    #[serde(default)]
    pub pre_ops: Vec<UserOp>,
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
    pub id: KeyID,
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
