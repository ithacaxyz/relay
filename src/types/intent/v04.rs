use super::{SignedCall, SignedCalls};
use crate::types::Key;
use alloy::{
    primitives::{B256, Keccak256, U256, keccak256},
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
    /// Sets the payment amount fields so it has the same behaviour as legacy Intent.
    pub fn set_legacy_payment_amount(&mut self, amount: U256) {
        self.prePaymentAmount = amount;
        self.prePaymentMaxAmount = amount;
        self.totalPaymentAmount = amount;
        self.totalPaymentMaxAmount = amount;
    }

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
}

impl SignedCalls for IntentV04 {
    fn as_eip712(&self) -> Result<impl SolStruct + Serialize + Send, alloy::sol_types::Error> {
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
}
