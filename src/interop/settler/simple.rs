use super::{SettlementError, Settler, SettlerId, VerificationResult};
use crate::{
    transactions::{RelayTransaction, interop::InteropBundle},
    types::{Call3, IEscrow, aggregate3Call},
};
use alloy::{
    primitives::{Address, B256, Bytes, ChainId, U256, map::HashMap},
    providers::{DynProvider, MULTICALL3_ADDRESS, Provider},
    rpc::types::TransactionRequest,
    signers::{Signer, local::PrivateKeySigner},
    sol,
    sol_types::{Eip712Domain, SolCall, SolValue},
};
use async_trait::async_trait;
use futures_util::future::try_join_all;
use itertools::Itertools;
use std::{collections::HashSet, time::Duration};

/// A simple settler implementation that does not require cross-chain attestation.
#[derive(Debug)]
pub struct SimpleSettler {
    /// Signer for signing settlement operations
    signer: PrivateKeySigner,
    /// Providers for each chain
    providers: HashMap<ChainId, DynProvider>,
}

impl SimpleSettler {
    /// Creates a new simple settler instance
    pub fn new(signer: PrivateKeySigner, providers: HashMap<ChainId, DynProvider>) -> Self {
        Self { signer, providers }
    }

    /// Gets a provider for the specified chain
    fn provider(&self, chain_id: ChainId) -> Result<&DynProvider, SettlementError> {
        self.providers.get(&chain_id).ok_or(SettlementError::UnsupportedChain(chain_id))
    }

    /// Fetches the EIP712 domain from the SimpleSettler contract
    async fn eip712_domain(
        &self,
        chain_id: ChainId,
        settler_address: Address,
    ) -> Result<Eip712Domain, SettlementError> {
        let provider = self.provider(chain_id)?;

        let contract = ISimpleSettler::new(settler_address, provider);
        let domain = contract.eip712Domain().call().await.map_err(|e| {
            SettlementError::InternalError(format!("Failed to fetch EIP712 domain: {e}"))
        })?;

        Ok(Eip712Domain::new(
            Some(domain.name.into()),
            Some(domain.version.into()),
            Some(domain.chainId),
            Some(domain.verifyingContract),
            None,
        ))
    }

    /// Builds the simplesettler write call data.
    async fn build_write_calldata(
        &self,
        sender: Address,
        settlement_id: B256,
        intent_chain: ChainId,
        source_chain: ChainId,
        settler_address: Address,
    ) -> Result<Bytes, SettlementError> {
        // Create the EIP712 message to sign
        let message = SettlementWrite {
            sender,
            settlementId: settlement_id,
            chainId: U256::from(intent_chain),
        };

        let signature = self
            .signer
            .sign_typed_data(&message, &self.eip712_domain(source_chain, settler_address).await?)
            .await
            .map_err(|e| SettlementError::InternalError(format!("Failed to sign: {e}")))?;

        Ok(ISimpleSettler::writeCall {
            sender,
            settlementId: settlement_id,
            chainId: U256::from(intent_chain),
            signature: signature.as_bytes().into(),
        }
        .abi_encode()
        .into())
    }

    /// Builds the settle call data for escrow by fetching escrow info from bundle
    fn build_settle_calldata(
        bundle: &InteropBundle,
        source_chain: ChainId,
        settlement_id: B256,
    ) -> Result<(Bytes, Address), SettlementError> {
        let escrow_info = bundle.get_escrows(source_chain, settlement_id)?;

        let settle_calldata =
            IEscrow::settleCall { escrowIds: escrow_info.escrow_ids }.abi_encode().into();

        Ok((settle_calldata, escrow_info.escrow_address))
    }

    /// Builds multicall data combining write and settle operations
    fn build_multicall(
        &self,
        write_calldata: Bytes,
        settle_calldata: Bytes,
        escrow_address: Address,
        settler_address: Address,
    ) -> Bytes {
        let calls = vec![
            Call3 { target: settler_address, allowFailure: false, callData: write_calldata },
            Call3 { target: escrow_address, allowFailure: false, callData: settle_calldata },
        ];

        aggregate3Call { calls }.abi_encode().into()
    }
}

#[async_trait]
impl Settler for SimpleSettler {
    fn id(&self) -> SettlerId {
        SettlerId::Simple
    }

    async fn build_execute_send_transaction(
        &self,
        _settlement_id: B256,
        _current_chain_id: ChainId,
        _source_chains: Vec<ChainId>,
        _orchestrator: Address,
        _intent_settler: Address,
    ) -> Result<Option<RelayTransaction>, SettlementError> {
        // The settlement is handled directly during intent execution
        Ok(None)
    }

    fn encode_settler_context(&self, chains: Vec<ChainId>) -> Result<Bytes, SettlementError> {
        // Encode the input chain IDs for the settler context
        let input_chain_ids: Vec<U256> =
            chains.iter().sorted().map(|chain_id| U256::from(*chain_id)).collect();

        // Simple settler doesn't need any context
        Ok(input_chain_ids.abi_encode().into())
    }

    async fn wait_for_verifications(
        &self,
        _bundle: &InteropBundle,
        _timeout: Duration,
    ) -> Result<VerificationResult, SettlementError> {
        // Simple settler doesn't need verification, always return success
        Ok(VerificationResult { verified_packets: vec![], failed_packets: vec![] })
    }

    async fn build_execute_receive_transactions(
        &self,
        bundle: &InteropBundle,
    ) -> Result<Vec<RelayTransaction>, SettlementError> {
        // Get all unique source chains from the bundle
        let source_chains = bundle.src_txs.iter().map(|tx| tx.chain_id()).collect::<HashSet<_>>();

        // Build write transactions for each destination
        let results = try_join_all(bundle.dst_txs.iter().map(async |dst_tx| {
            let settlement_id = dst_tx.eip712_digest().ok_or(SettlementError::MissingIntent)?;
            let destination_chain = dst_tx.chain_id();
            let quote = dst_tx.quote().ok_or(SettlementError::MissingIntent)?;
            let sender = quote.orchestrator;
            let intent_settler = quote.intent.settler;

            let txs = try_join_all(source_chains.iter().map(async |&source_chain| {
                let write_calldata = self
                    .build_write_calldata(
                        sender,
                        settlement_id,
                        destination_chain,
                        source_chain,
                        intent_settler,
                    )
                    .await?;

                let (settle_calldata, escrow_address) =
                    Self::build_settle_calldata(bundle, source_chain, settlement_id)?;

                let multicall_data = self.build_multicall(
                    write_calldata,
                    settle_calldata,
                    escrow_address,
                    intent_settler,
                );

                let tx_request = TransactionRequest::default()
                    .to(MULTICALL3_ADDRESS)
                    .input(multicall_data.clone().into());
                let gas_limit = self.provider(source_chain)?.estimate_gas(tx_request).await?;

                Ok::<_, SettlementError>(RelayTransaction::new_internal(
                    MULTICALL3_ADDRESS,
                    multicall_data,
                    source_chain,
                    gas_limit,
                ))
            }))
            .await?;
            Ok::<_, SettlementError>(txs)
        }))
        .await?;

        Ok(results.into_iter().flatten().collect())
    }
}

sol! {
    /// SimpleSettler interface
    #[sol(rpc)]
    interface ISimpleSettler {
        /// Anyone can write settlement details with a valid signature from the owner.
        /// This prevents the need for the owner to make on-chain transactions.
        /// Replaying the signature is harmless as it only sets the value to true.
        function write(address sender, bytes32 settlementId, uint256 chainId, bytes calldata signature) external;

        /// Returns the EIP712 domain separator information
        function eip712Domain()
            public
            view
            virtual
            returns (
                bytes1 fields,
                string memory name,
                string memory version,
                uint256 chainId,
                address verifyingContract,
                bytes32 salt,
                uint256[] memory extensions
            );
    }

    #[derive(Debug)]
    struct SettlementWrite {
        address sender;
        bytes32 settlementId;
        uint256 chainId;
    }
}
