//! RPC account-related request and response types.

use super::{AuthorizeKey, AuthorizeKeyResponse, KeySignature, SendPreparedCallsResponse};
use crate::{
    error::{AuthError, KeysError},
    types::{Key, KeyHashWithID, KeyID, PREPAccount, SignedQuote, UserOp},
};
use alloy::{
    eips::eip7702::SignedAuthorization,
    primitives::{Address, B256, ChainId, Signature},
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
            .map(|key_signature| {
                let hash = key_signature.key_hash();
                let digest = Key::id_digest_from_hash(hash, self.context.account.address);

                Signature::from_raw(&key_signature.value)
                    .and_then(|signature| {
                        signature.recover_address_from_prehash(&digest).map(|id| KeyHashWithID {
                            hash,
                            id,
                            signature,
                        })
                    })
                    .map_err(|_| {
                        KeysError::InvalidKeyIdSignature(key_signature.value.clone()).into()
                    })
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeAccountParameters {
    /// The [`SignedQuote`] of the prepared call bundle.
    pub context: SignedQuote,
    /// Signature of the `wallet_prepareUpgradeAccount` digest.
    #[serde(with = "alloy::serde::displayfromstr")]
    pub signature: Signature,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Quote, Signed};
    use alloy::{
        eips::{eip1559::Eip1559Estimation, eip7702::Authorization},
        primitives::U256,
    };
    use std::time::{Duration, UNIX_EPOCH};

    #[test]
    fn upgrade_account_params_serde() {
        let signature = Signature::new(U256::ZERO, U256::ZERO, false);
        let acc = UpgradeAccountParameters {
            context: Signed::new_unchecked(
                Quote {
                    chain_id: 0,
                    op: Default::default(),
                    tx_gas: 0,
                    native_fee_estimate: Eip1559Estimation {
                        max_fee_per_gas: 0,
                        max_priority_fee_per_gas: 0,
                    },
                    ttl: UNIX_EPOCH + Duration::from_secs(0),
                    authorization_address: None,
                    is_preop: false,
                    entrypoint: Address::random(),
                },
                signature,
                B256::ZERO,
            ),
            signature,
            authorization: Authorization {
                chain_id: Default::default(),
                address: Default::default(),
                nonce: 0,
            }
            .into_signed(signature),
        };
        let json = serde_json::to_string(&acc).unwrap();
        let from_json = serde_json::from_str::<UpgradeAccountParameters>(&json).unwrap();
        assert_eq!(acc, from_json);

        let s = r#"{"context":{"chainId":0,"op":{"eoa":"0x0000000000000000000000000000000000000000","executionData":"0x","nonce":"0x0","payer":"0x0000000000000000000000000000000000000000","paymentToken":"0x0000000000000000000000000000000000000000","paymentRecipient":"0x0000000000000000000000000000000000000000","paymentAmount":"0x0","paymentMaxAmount":"0x0","paymentPerGas":"0x0","combinedGas":"0x0","signature":"0x","initData":"0x","encodedPreOps":[],"paymentSignature":"0x"},"txGas":"0x0","nativeFeeEstimate":{"maxFeePerGas":"0x0","maxPriorityFeePerGas":"0x0"},"ttl":0,"authorizationAddress":null,"isPreop":false,"r":"0x0","s":"0x0","yParity":"0x0","v":"0x0","hash":"0x0000000000000000000000000000000000000000000000000000000000000000"},"signature":"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001b","authorization":{"chainId":"0x0","address":"0x0000000000000000000000000000000000000000","nonce":"0x0","yParity":"0x0","r":"0x0","s":"0x0"}}
"#;
        let from_json = serde_json::from_str::<UpgradeAccountParameters>(s).unwrap();
        assert_eq!(acc, from_json);
    }
}
