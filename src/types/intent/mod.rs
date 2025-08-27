use super::{Call, IDelegation::authorizeCall, Key, MerkleLeafInfo};
use crate::{
    error::{IntentError, MerkleError},
    types::{
        CallPermission,
        IthacaAccount::{setCanExecuteCall, setSpendLimitCall},
        Orchestrator,
        rpc::{
            AddressOrNative, AuthorizeKey, AuthorizeKeyResponse, BalanceOverrides, Permission,
            SpendPermission,
        },
    },
};
use alloy::{
    dyn_abi::TypedData,
    eips::eip7702::SignedAuthorization,
    primitives::{Address, B256, Bytes, ChainId, U256, aliases::U192, map::HashMap},
    providers::DynProvider,
    sol,
    sol_types::{SolCall, SolStruct, SolValue},
    uint,
};
use serde::{Deserialize, Serialize};
use std::future::Future;

mod r#enum;
mod v04;

pub use r#enum::Intent;
pub use v04::IntentV04;

/// Nonce prefix to signal that the payload is to be signed with EIP-712 without the chain ID.
pub const MULTICHAIN_NONCE_PREFIX: U256 = uint!(0xc1d0_U256);

/// Nonce prefix to signal that the payload is to be signed with EIP-712 without the chain ID.
pub const MULTICHAIN_NONCE_PREFIX_U192: U192 = uint!(0xc1d0_U192);

sol! {
    /// A struct to hold the fields for a PreCall.
    /// Like a Intent with a subset of fields.
    #[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct SignedCall {
        /// The user's address.
        ///
        /// This can be set to `address(0)`, which allows it to be
        /// coalesced to the parent Intent's EOA.
        address eoa;
        /// An encoded array of calls, using ERC7579 batch execution encoding.
        ///
        /// `abi.encode(calls)`, where `calls` is of type `Call[]`.
        /// This allows for more efficient safe forwarding to the EOA.
        bytes executionData;
        /// Per delegated EOA. Same logic as the `nonce` in Intent.
        uint256 nonce;
        /// The wrapped signature.
        ///
        /// `abi.encodePacked(innerSignature, keyHash, prehash)`.
        bytes signature;
    }

    /// A struct to fund an account on an output chain from a multi chain intent.
    #[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Transfer {
        address token;
        uint256 amount;
    }
}

/// A partial [`Intent`] used for fee estimation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PartialIntent {
    /// The user's address.
    pub eoa: Address,
    /// An encoded array of calls, using ERC7579 batch execution encoding.
    ///
    /// The format is `abi.encode(calls)`, where `calls` is an array of type `Call[]`.
    ///
    /// This allows for more efficient safe forwarding to the EOA.
    pub execution_data: Bytes,
    /// Per delegated EOA.
    pub nonce: U256,
    /// Optional payer of the gas.
    pub payer: Option<Address>,
    /// Optional array of encoded PreCalls that will be verified and executed before the
    /// verification of the overall Intent.
    pub pre_calls: Vec<SignedCall>,
    /// Funds required in the destination chain.
    pub fund_transfers: Vec<(Address, U256)>,
}

/// Context for fee estimation that groups execution-related parameters.
#[derive(Debug, Clone)]
pub struct FeeEstimationContext {
    /// The token to use for fee payment.
    pub fee_token: Address,
    /// Optional stored authorization for EIP-7702 delegation.
    pub stored_authorization: Option<SignedAuthorization>,
    /// The account key used for signing.
    pub account_key: Key,
    /// Whether to override key slots in state.
    pub key_slot_override: bool,
    /// The kind of intent being estimated.
    pub intent_kind: IntentKind,
    /// State overrides for simulation.
    pub state_overrides: alloy::rpc::types::state::StateOverride,
    /// Balance overrides for simulation.
    pub balance_overrides: BalanceOverrides,
}

mod eip712 {
    use crate::types::Call;
    use alloy::sol;

    sol! {
        #[derive(serde::Serialize)]
        struct SignedCall {
            bool multichain;
            address eoa;
            Call[] calls;
            uint256 nonce;
        }
    }
}

impl SignedCall {
    /// Returns a new SignedCall with the signature set.
    pub fn with_signature(mut self, signature: Bytes) -> Self {
        self.signature = signature;
        self
    }

    /// Returns all authorized keys with their permissions.
    pub fn authorized_keys_with_permissions(
        &self,
    ) -> Result<Vec<AuthorizeKeyResponse>, alloy::sol_types::Error> {
        let mut permissions: HashMap<B256, Vec<Permission>> = HashMap::default();

        for call in self.calls()? {
            // try decoding as a setSpendLimit call first.
            if let Ok(setSpendLimitCall { keyHash, token, period, limit }) =
                setSpendLimitCall::abi_decode(&call.data)
            {
                permissions
                    .entry(keyHash)
                    .or_default()
                    .push(SpendPermission { limit, period, token }.into());
                continue;
            }

            // if it wasn't a setSpendLimit, try decoding as a setCanExecute.
            if let Ok(setCanExecuteCall { keyHash, target: to, fnSel: selector, can }) =
                setCanExecuteCall::abi_decode(&call.data)
                && can
            {
                permissions
                    .entry(keyHash)
                    .or_default()
                    .push(CallPermission { selector, to }.into());
            }
        }

        Ok(self
            .authorized_keys()?
            .into_iter()
            .map(|key| {
                let hash = key.key_hash();
                AuthorizeKeyResponse {
                    authorize_key: AuthorizeKey {
                        permissions: permissions.remove(&hash).unwrap_or_default(),
                        key,
                    },
                    hash,
                }
            })
            .collect())
    }
}

/// Shared behaviour between [`Intent`] and [`PreCall`].
pub trait SignedCalls {
    /// Returns `executionData`.
    fn execution_data(&self) -> &[u8];

    /// Returns `nonce`.
    fn nonce(&self) -> U256;

    /// Returns the decoded calls from `executionData`.
    fn calls(&self) -> Result<Vec<Call>, alloy::sol_types::Error> {
        <Vec<Call>>::abi_decode(self.execution_data())
    }

    /// Returns all keys authorized in `executionData`.
    fn authorized_keys_from_execution_data(
        &self,
    ) -> Result<impl Iterator<Item = Key>, alloy::sol_types::Error> {
        // Decode keys from the execution data.
        Ok(self.calls()?.into_iter().filter_map(|call| {
            // Attempt to decode the call as an authorizeCall; ignore if unsuccessful.
            authorizeCall::abi_decode(&call.data).ok().map(|decoded| decoded.key)
        }))
    }

    /// Returns all keys authorized in the current intent.
    fn authorized_keys(&self) -> Result<Vec<Key>, alloy::sol_types::Error> {
        Ok(self.authorized_keys_from_execution_data()?.collect())
    }

    /// Whether this intent is multichain.
    ///
    /// If the intent is multichain, the EIP712 domain used for the signing hash of the intent
    /// should not include a chain ID.
    fn is_multichain(&self) -> bool {
        self.nonce() >> 240 == MULTICHAIN_NONCE_PREFIX
    }

    /// Get the EIP712 encoding of the intent.
    fn as_eip712(&self) -> Result<impl SolStruct + Serialize + Send, alloy::sol_types::Error>;

    /// Computes the EIP-712 digest that the user must sign.
    fn compute_eip712_data(
        &self,
        orchestrator_address: Address,
        provider: &DynProvider,
    ) -> impl Future<Output = eyre::Result<(B256, TypedData)>> + Send
    where
        Self: Sync,
    {
        async move {
            // Create the orchestrator instance with the same overrides.
            let orchestrator = Orchestrator::new(orchestrator_address, provider);

            // Prepare the EIP-712 payload and domain
            let payload = self.as_eip712()?;
            let domain = orchestrator.eip712_domain(self.is_multichain()).await?;

            // Return the computed signing hash (digest).
            let digest = payload.eip712_signing_hash(&domain);
            let typed_data = TypedData::from_struct(&payload, Some(domain));

            debug_assert_eq!(Ok(digest), typed_data.eip712_signing_hash());

            Ok((digest, typed_data))
        }
    }
}

impl SignedCalls for SignedCall {
    fn execution_data(&self) -> &[u8] {
        &self.executionData
    }

    fn nonce(&self) -> U256 {
        self.nonce
    }

    fn as_eip712(&self) -> Result<impl SolStruct + Serialize + Send, alloy::sol_types::Error> {
        Ok(eip712::SignedCall {
            multichain: self.is_multichain(),
            eoa: self.eoa,
            calls: self.calls()?,
            nonce: self.nonce,
        })
    }
}

/// Kind of intent to be simulated and created.
#[derive(Debug, Clone)]
pub enum IntentKind {
    /// Single chain intent.
    Single,
    /// Output of a multi chain intent.
    MultiOutput {
        /// The leaf index in the merkle tree.
        leaf_index: usize,
        /// Fund transfers (token address, amount) pairs.
        fund_transfers: Vec<(Address, U256)>,
        /// Settler context (ABI encoded).
        settler_context: Bytes,
    },
    /// Input of a multi chain intent.
    MultiInput {
        /// The merkle leaf information.
        leaf_info: MerkleLeafInfo,
        /// The fee to pay, if precomputed as `(token address, amount)`. If this is `None`, the
        /// fee will be estimated as normal.
        fee: Option<(Address, U256)>,
    },
}

impl IntentKind {
    /// Returns `true` if this is [`IntentKind::Single`].
    pub fn is_single(&self) -> bool {
        matches!(self, IntentKind::Single)
    }

    /// Returns `true` if this is [`IntentKind::MultiOutput`].
    pub fn is_multi_output(&self) -> bool {
        matches!(self, IntentKind::MultiOutput { .. })
    }

    /// Returns `true` if this is [`IntentKind::MultiInput`].
    pub fn is_multi_input(&self) -> bool {
        matches!(self, IntentKind::MultiInput { .. })
    }

    /// Returns the fund transfers if dealing with a multi chain intent.
    pub fn fund_transfers(&self) -> Vec<(Address, U256)> {
        match self {
            IntentKind::MultiOutput { fund_transfers, .. } => fund_transfers.clone(),
            _ => vec![],
        }
    }

    /// Returns the fee for a multichain input if it is set.
    pub fn multi_input_fee(&self) -> Option<U256> {
        match self {
            IntentKind::MultiInput { fee: Some((_, amount)), .. } => Some(*amount),
            _ => None,
        }
    }

    /// Returns the settler context if this is a MultiOutput intent.
    pub fn settler_context(&self) -> Bytes {
        match self {
            IntentKind::MultiOutput { settler_context, .. } => settler_context.clone(),
            _ => Bytes::default(),
        }
    }

    /// Returns the merkle leaf information for multichain intents.
    ///
    /// Returns an error for single chain intents.
    pub fn merkle_leaf_info(&self) -> Result<MerkleLeafInfo, IntentError> {
        match self {
            IntentKind::MultiOutput { leaf_index, .. } => {
                Ok(MerkleLeafInfo { total: *leaf_index + 1, index: *leaf_index })
            }
            IntentKind::MultiInput { leaf_info, .. } => Ok(*leaf_info),
            IntentKind::Single => Err(IntentError::from(MerkleError::LeafHashError(
                "Cannot build merkle tree for single chain intent".to_string(),
            ))),
        }
    }
}

/// Context for building a funding intent in multichain operations.
#[derive(Debug, Clone)]
pub struct FundingIntentContext {
    /// The EOA that will escrow funds
    pub eoa: Address,
    /// The chain where funds will be escrowed
    pub chain_id: ChainId,
    /// The asset to be escrowed (native or ERC20)
    pub asset: AddressOrNative,
    /// The amount to escrow
    pub amount: U256,
    /// The fee token to use for gas payment
    pub fee_token: Address,
    /// The output intent digest this funding will support
    pub output_intent_digest: B256,
    /// The destination chain ID where funds will be used
    pub output_chain_id: ChainId,
}

/// A funding source.
///
/// A funding source is an amount of assets on a specific chain, and an associated cost with using
/// those funds.
#[derive(Debug, Clone)]
pub struct FundSource {
    /// The chain ID the funds are on.
    pub chain_id: ChainId,
    /// The amount of funds on that chain.
    pub amount: U256,
    /// The address of the funds.
    ///
    /// # Note
    ///
    /// This can (and probably will!) differ from chain to chain.
    pub address: Address,
    /// The cost of transferring the funds.
    ///
    /// The cost is in base units of the funds we are trying to transfer; in the future, we may
    /// want to separate this out.
    pub cost: U256,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signers::DynSigner;
    use alloy::{
        dyn_abi::Eip712Domain,
        primitives::{Address, Bytes, address, b256, bytes},
        sol_types::SolStruct,
    };

    #[test]
    fn is_multichain() {
        assert!(!Intent::default().is_multichain());
        assert!(
            Intent::v04().with_nonce(U256::from(MULTICHAIN_NONCE_PREFIX << 240)).is_multichain()
        );
        assert!(
            Intent::v04()
                .with_nonce((MULTICHAIN_NONCE_PREFIX << 240) | U256::from(31338))
                .is_multichain()
        )
    }

    #[test]
    fn intent_eip712_digest() {
        let mut intent = Intent::v04()
            .with_eoa(address!("0x7b9fc63d6d9e8f94e90d1b0abfc3f611de2638d0"))
            .with_execution_data(bytes!(
                "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000007fa9385be102ac3eac297483dd6233d62b3e149600000000000000000000000000000000000000000000000000000000628c3be0000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001443c78f395000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000e32c67f61a578060c3776c5384f017e2f74184e2aeb81b3679c6d44b6db88522eeffffffff000000000000000000000000000000000000000000000000000000000000002c3d3d3d3d363d3d37363d73f62849f9a0b5bf2913b396098f7c7019b51a820a5af43d3d93803e602a57fd5bf300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            ))
            .with_nonce(U256::from(31338))
            .with_payer(Address::ZERO)
            .with_payment_token(address!("0xc7183455a4c133ae270771860664b6b7ec320bb1"))
            .with_pre_payment_max_amount(U256::from(3822601006u64))
            .with_total_payment_max_amount(U256::from(3822601006u64))
            .with_combined_gas(U256::from(10_000_000u64))
            .with_encoded_pre_calls(vec![])
            .with_encoded_fund_transfers(vec![bytes!("")])
            .with_settler(Address::ZERO)
            .with_expiry(U256::ZERO)
            .with_settler_context(bytes!(""))
            .with_pre_payment_amount(U256::from(3822601006u64))
            .with_total_payment_amount(U256::from(3822601006u64))
            .with_payment_recipient(Address::ZERO)
            .with_signature(bytes!(""))
            .with_payment_signature(bytes!(""))
            .with_supported_account_implementation(Address::ZERO)
            .with_funder(Address::ZERO)
            .with_funder_signature(bytes!(""))
            .with_is_multichain(false);

        // Single chain op
        intent = intent.with_nonce(U256::from(31338));
        assert_eq!(
            intent.as_eip712().unwrap().eip712_signing_hash(&Eip712Domain::new(
                Some("Orchestrator".into()),
                Some("0.0.1".into()),
                Some(U256::from(31337)),
                Some(address!("0x307AF7d28AfEE82092aA95D35644898311CA5360")),
                None
            )),
            b256!("0x73441b6d0e26f007fe0502197dd6a38ba23390793db0857d44fcb886c1951a73")
        );

        // Multichain op
        intent = intent.with_nonce((MULTICHAIN_NONCE_PREFIX << 240) | U256::from(31338));
        assert_eq!(
            intent.as_eip712().unwrap().eip712_signing_hash(&Eip712Domain::new(
                Some("Orchestrator".into()),
                Some("0.0.1".into()),
                None,
                Some(address!("0x307AF7d28AfEE82092aA95D35644898311CA5360")),
                None
            )),
            b256!("0x23525bbb9857ea723c78e0075a63c794c0e6212ca43f5192fb181b5de34a9136")
        );
    }

    #[tokio::test]
    async fn intent_with_signature() {
        let mut intent = Intent::v04()
            .with_eoa(address!("0xE017A867c7204Fd596aE3141a5B194596849A196"))
            .with_execution_data(bytes!(
                "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000007fa9385be102ac3eac297483dd6233d62b3e1496000000000000000000000000000000000000000000000000000000009009e8ec000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000443c78f3950000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            ))
            .with_nonce(U256::from(1))
            .with_payer(Address::ZERO)
            .with_payment_token(address!("0xc7183455a4c133ae270771860664b6b7ec320bb1"))
            .with_pre_payment_max_amount(U256::from(1021265804))
            .with_total_payment_max_amount(U256::from(1021265804))
            .with_combined_gas(U256::from(10000000u64))
            .with_encoded_pre_calls(vec![])
            .with_encoded_fund_transfers(vec![bytes!("")])
            .with_settler(Address::ZERO)
            .with_expiry(U256::ZERO)
            .with_settler_context(bytes!(""))
            .with_pre_payment_amount(U256::from(1021265804))
            .with_total_payment_amount(U256::from(1021265804))
            .with_payment_recipient(Address::ZERO)
            .with_signature(bytes!(""))
            .with_payment_signature(bytes!(""))
            .with_supported_account_implementation(Address::ZERO)
            .with_funder(Address::ZERO)
            .with_funder_signature(bytes!(""))
            .with_is_multichain(false);

        let expected_digest =
            b256!("0x01cdc1e4abcc1e13c42346be0202934a6d29e74a956779e1ea49136ce3f13b70");
        assert_eq!(
            intent.as_eip712().unwrap().eip712_signing_hash(&Eip712Domain::new(
                Some("Orchestrator".into()),
                Some("0.0.1".into()),
                None,
                Some(address!("0x307AF7d28AfEE82092aA95D35644898311CA5360")),
                None
            )),
            expected_digest
        );

        let signer = DynSigner::from_signing_key(
            "0x44a8f44ef7307087c960f8bfcbd95f7a1c9a2f505d438d1750dc947cfedb4b4a",
        )
        .await
        .unwrap();
        intent = intent
            .with_signature(signer.sign_hash(&expected_digest).await.unwrap().as_bytes().into());

        assert_eq!(
            *intent.signature(),
            bytes!(
                "0x73b4adced3c0df6ad95813d47d1f32d3fd7f9b5da437ebb34d9748b8f64a2a663c938d41f95f4d65014f62caf29b5b7a6123c4166f579dc3d728dc6f6a8521e91b"
            )
        );

        assert_eq!(
            Bytes::from(intent.abi_encode()),
            bytes!(
                "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000e017a867c7204fd596ae3141a5b194596849a19600000000000000000000000000000000000000000000000000000000000002c000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c7183455a4c133ae270771860664b6b7ec320bb1000000000000000000000000000000000000000000000000000000003cdf478c000000000000000000000000000000000000000000000000000000003cdf478c000000000000000000000000000000000000000000000000000000000098968000000000000000000000000000000000000000000000000000000000000004200000000000000000000000000000000000000000000000000000000000000440000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004a000000000000000000000000000000000000000000000000000000000000004c0000000000000000000000000000000000000000000000000000000003cdf478c000000000000000000000000000000000000000000000000000000003cdf478c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004e00000000000000000000000000000000000000000000000000000000000000560000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000007fa9385be102ac3eac297483dd6233d62b3e1496000000000000000000000000000000000000000000000000000000009009e8ec000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000443c78f3950000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004173b4adced3c0df6ad95813d47d1f32d3fd7f9b5da437ebb34d9748b8f64a2a663c938d41f95f4d65014f62caf29b5b7a6123c4166f579dc3d728dc6f6a8521e91b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
    }
}
