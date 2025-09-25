use super::{SignedCall, SignedCalls};
use crate::{
    error::RelayError,
    types::{Key, VersionedContract},
};
use alloy::{
    dyn_abi::TypedData,
    primitives::{B256, ChainId, Keccak256, U256, keccak256},
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
    struct IntentV05 {
        address eoa;
        bytes executionData;
        uint256 nonce;
        address payer;
        address paymentToken;
        uint256 paymentMaxAmount;
        uint256 combinedGas;
        bytes[] encodedPreCalls;
        bytes[] encodedFundTransfers;
        address settler;
        uint256 expiry;
        bool isMultichain;
        address funder;
        bytes funderSignature;
        bytes settlerContext;
        uint256 paymentAmount;
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
            uint256 paymentMaxAmount;
            uint256 combinedGas;
            bytes[] encodedPreCalls;
            bytes[] encodedFundTransfers;
            address settler;
            uint256 expiry;
        }
    }
}

impl IntentV05 {
    /// Calculate a digest of the [`IntentV05`], used for checksumming.
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
        hasher.update(self.paymentMaxAmount.to_be_bytes::<32>());
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
            paymentMaxAmount: self.paymentMaxAmount,
            combinedGas: self.combinedGas,
            encodedPreCalls: self.encodedPreCalls.clone(),
            encodedFundTransfers: self.encodedFundTransfers.clone(),
            settler: self.settler,
            expiry: self.expiry,
        })
    }
}

impl SignedCalls for IntentV05 {
    fn execution_data(&self) -> &[u8] {
        &self.executionData
    }

    fn nonce(&self) -> U256 {
        self.nonce
    }

    /// Returns all keys authorized in the current [`IntentV05`] including `pre_calls` and
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

    fn compute_eip712_data(
        &self,
        orchestrator: &VersionedContract,
        chain_id: ChainId,
    ) -> Result<(B256, alloy::dyn_abi::TypedData), RelayError> {
        // Prepare the EIP-712 payload and domain
        let payload = self.as_eip712()?;
        let domain = orchestrator.eip712_domain((!self.is_multichain()).then_some(chain_id));

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
        assert!(!Intent::v05().is_nonce_multichain());
        assert!(!Intent::v05().is_interop());
        assert!(Intent::v05().with_nonce(MULTICHAIN_NONCE_PREFIX << 240).is_nonce_multichain());
        assert!(
            Intent::v05()
                .with_nonce((MULTICHAIN_NONCE_PREFIX << 240) | U256::from(31338))
                .is_nonce_multichain()
        );
        assert!(Intent::v05().with_interop().is_interop());
    }

    #[test]
    fn intent_eip712_digest() {
        let mut intent = Intent::v05()
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
        // Get the V05 variant from the enum
        let v05_intent = match &intent {
            Intent::V05(v) => v,
            _ => panic!("Expected V05 variant"),
        };
        assert_eq!(
            v05_intent.as_eip712().unwrap().eip712_signing_hash(&Eip712Domain::new(
                Some("Orchestrator".into()),
                Some("0.0.1".into()),
                Some(U256::from(31337)),
                Some(address!("0x307AF7d28AfEE82092aA95D35644898311CA5360")),
                None
            )),
            b256!("0xdf5d420f5e7beef3546f5705e54439e944a8e525140bf864594c0cfeb86972a1")
        );

        // Multichain op
        intent = intent.with_nonce((MULTICHAIN_NONCE_PREFIX << 240) | U256::from(31338));
        let v05_intent = match &intent {
            Intent::V05(v) => v,
            _ => panic!("Expected V05 variant"),
        };
        assert_eq!(
            v05_intent.as_eip712().unwrap().eip712_signing_hash(&Eip712Domain::new(
                Some("Orchestrator".into()),
                Some("0.0.1".into()),
                None,
                Some(address!("0x307AF7d28AfEE82092aA95D35644898311CA5360")),
                None
            )),
            b256!("0xb05ca90f95127ad9e7be1d6f614b818619f69b3eb36b9ad1b657dc7a6596bc87")
        );
    }

    #[tokio::test]
    async fn intent_with_signature() {
        let mut intent = Intent::v05()
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
            b256!("0xe881af3d38cab4d06ae5f92b65e32e0837b55b6cd20ce683eefeecdcbe0a5f16");
        let v05_intent = match &intent {
            Intent::V05(v) => v,
            _ => panic!("Expected V05 variant"),
        };
        assert_eq!(
            v05_intent.as_eip712().unwrap().eip712_signing_hash(&Eip712Domain::new(
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
                "0x786b2d7b6190f3781a9530d77e17c9476e5757eeeb30e1a94836473c13f96d010dc9d0672e68ae516bbb69459a3818679206b0d2b158b239e7ffe2083d1a366f1b"
            )
        );

        assert_eq!(
            Bytes::from(intent.abi_encode()),
            bytes!(
                "0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000e017a867c7204fd596ae3141a5b194596849a196000000000000000000000000000000000000000000000000000000000000028000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c7183455a4c133ae270771860664b6b7ec320bb1000000000000000000000000000000000000000000000000000000003cdf478c000000000000000000000000000000000000000000000000000000000098968000000000000000000000000000000000000000000000000000000000000003e00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004600000000000000000000000000000000000000000000000000000000000000480000000000000000000000000000000000000000000000000000000003cdf478c000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004a00000000000000000000000000000000000000000000000000000000000000520000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001400000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000007fa9385be102ac3eac297483dd6233d62b3e1496000000000000000000000000000000000000000000000000000000009009e8ec000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000443c78f39500000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000041786b2d7b6190f3781a9530d77e17c9476e5757eeeb30e1a94836473c13f96d010dc9d0672e68ae516bbb69459a3818679206b0d2b158b239e7ffe2083d1a366f1b000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
            )
        );
    }
}
