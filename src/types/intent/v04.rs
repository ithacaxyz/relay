use super::{SignedCall, SignedCalls};
use crate::{
    error::RelayError,
    types::{Key, Orchestrator, VersionedContract},
};
use alloy::{
    dyn_abi::TypedData,
    primitives::{B256, Keccak256, U256, keccak256},
    providers::DynProvider,
    sol,
    sol_types::{SolStruct, SolValue},
};
use serde::{Deserialize, Serialize};

sol! {
    /// A struct to hold the intent fields.
    ///
    /// Since L2s already include calldata compression with savings forwarded to users,
    /// we don't need to be too concerned about calldata overhead.
    #[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct IntentV04 {
        address eoa;
        bytes executionData;
        uint256 nonce;
        address payer;
        address paymentToken;
        uint256 prePaymentMaxAmount;
        uint256 totalPaymentMaxAmount;
        uint256 combinedGas;
        bytes[] encodedPreCalls;
        bytes[] encodedFundTransfers;
        address settler;
        uint256 expiry;
        ////////////////////////////////////////////////////////////////////////
        // Additional Fields (Not included in EIP-712)
        ////////////////////////////////////////////////////////////////////////
        bool isMultichain;
        address funder;
        bytes funderSignature;
        bytes settlerContext;
        uint256 prePaymentAmount;
        uint256 totalPaymentAmount;
        address paymentRecipient;
        bytes signature;
        bytes paymentSignature;
        address supportedAccountImplementation;
    }
}

mod eip712 {
    use crate::types::Call;
    use alloy::sol;

    sol! {
        #[derive(serde::Serialize)]
        struct Intent {
            bool multichain;
            address eoa;
            Call[] calls;
            uint256 nonce;
            address payer;
            address paymentToken;
            uint256 prePaymentMaxAmount;
            uint256 totalPaymentMaxAmount;
            uint256 combinedGas;
            bytes[] encodedPreCalls;
            bytes[] encodedFundTransfers;
            address settler;
            uint256 expiry;
        }
    }
}

impl IntentV04 {
    /// Calculate a digest of the [`IntentV04`], used for checksumming.
    ///
    /// # Note
    ///
    /// Only some fields are hashed.
    pub fn digest(&self) -> B256 {
        let mut hasher = Keccak256::new();
        hasher.update([self.is_multichain() as u8]);
        hasher.update(self.eoa);
        hasher.update(&self.executionData);
        hasher.update(self.nonce.to_be_bytes::<32>());
        hasher.update(self.payer);
        hasher.update(self.paymentToken);
        hasher.update(self.prePaymentMaxAmount.to_be_bytes::<32>());
        hasher.update(self.totalPaymentMaxAmount.to_be_bytes::<32>());
        hasher.update(self.combinedGas.to_be_bytes::<32>());
        let pre_calls_hash = {
            let mut hasher = Keccak256::new();
            for pre_call in self.encodedPreCalls.iter() {
                hasher.update(keccak256(pre_call));
            }
            hasher.finalize()
        };
        hasher.update(pre_calls_hash);
        for transfer in &self.encodedFundTransfers {
            hasher.update(transfer);
        }
        hasher.update(self.settler);
        hasher.update(self.expiry.to_be_bytes::<32>());
        hasher.update(self.supportedAccountImplementation);
        hasher.finalize()
    }

    /// Returns the EIP712 representation of this intent.
    pub fn as_eip712(&self) -> Result<eip712::Intent, alloy::sol_types::Error> {
        Ok(eip712::Intent {
            multichain: self.is_multichain(),
            eoa: self.eoa,
            calls: self.calls()?,
            nonce: self.nonce,
            payer: self.payer,
            paymentToken: self.paymentToken,
            prePaymentMaxAmount: self.prePaymentMaxAmount,
            totalPaymentMaxAmount: self.totalPaymentMaxAmount,
            combinedGas: self.combinedGas,
            encodedPreCalls: self.encodedPreCalls.clone(),
            encodedFundTransfers: self.encodedFundTransfers.clone(),
            settler: self.settler,
            expiry: self.expiry,
        })
    }
}

impl SignedCalls for IntentV04 {
    fn execution_data(&self) -> &[u8] {
        &self.executionData
    }

    fn nonce(&self) -> U256 {
        self.nonce
    }

    /// Returns all keys authorized in the current [`IntentV04`] including `pre_calls` and
    /// `executionData`.
    fn authorized_keys(&self) -> Result<Vec<Key>, alloy::sol_types::Error> {
        let mut all_keys: Vec<Key> = self.authorized_keys_from_execution_data()?.collect();

        // Add keys from pre_calls
        for encoded_precall in &self.encodedPreCalls {
            let pre_call = SignedCall::abi_decode(encoded_precall)?;
            all_keys.extend(pre_call.authorized_keys_from_execution_data()?);
        }

        Ok(all_keys)
    }

    async fn compute_eip712_data(
        &self,
        orchestrator: &VersionedContract,
        provider: &DynProvider,
    ) -> Result<(B256, TypedData), RelayError>
    where
        Self: Sync,
    {
        // Create the orchestrator instance with the same overrides.
        let orchestrator = Orchestrator::new(orchestrator.clone(), provider);

        // Prepare the EIP-712 payload and domain
        let payload = self.as_eip712()?;
        let domain = orchestrator.eip712_domain(self.is_multichain());

        // Return the computed signing hash (digest).
        let digest = payload.eip712_signing_hash(&domain);
        let typed_data = TypedData::from_struct(&payload, Some(domain));

        debug_assert_eq!(Ok(digest), typed_data.eip712_signing_hash());

        Ok((digest, typed_data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        signers::DynSigner,
        types::intent::{Intent, MULTICHAIN_NONCE_PREFIX},
    };
    use alloy::{
        dyn_abi::Eip712Domain,
        primitives::{Address, Bytes, address, b256, bytes},
        sol_types::SolStruct,
    };

    #[test]
    fn is_multichain() {
        assert!(!Intent::v04().is_nonce_multichain());
        assert!(!Intent::v04().is_interop());
        assert!(Intent::v04().with_nonce(MULTICHAIN_NONCE_PREFIX << 240).is_nonce_multichain());
        assert!(
            Intent::v04()
                .with_nonce((MULTICHAIN_NONCE_PREFIX << 240) | U256::from(31338))
                .is_nonce_multichain()
        );
        assert!(Intent::v04().with_interop().is_interop());
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
            .with_funder_signature(bytes!(""));

        // Single chain op
        intent = intent.with_nonce(U256::from(31338));
        // Get the V04 variant from the enum
        let v04_intent = intent.as_v04().expect("v04 variant");
        assert_eq!(
            v04_intent.as_eip712().unwrap().eip712_signing_hash(&Eip712Domain::new(
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
        let v04_intent = intent.as_v04().expect("v04 variant");
        assert_eq!(
            v04_intent.as_eip712().unwrap().eip712_signing_hash(&Eip712Domain::new(
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
            .with_funder_signature(bytes!(""));

        let expected_digest =
            b256!("0x01cdc1e4abcc1e13c42346be0202934a6d29e74a956779e1ea49136ce3f13b70");
        let v04_intent = match &intent {
            Intent::V04(v) => v,
            _ => panic!("Expected V04 variant"),
        };
        assert_eq!(
            v04_intent.as_eip712().unwrap().eip712_signing_hash(&Eip712Domain::new(
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
