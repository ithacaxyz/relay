//! LayerZero settler for cross-chain settlement attestation.
//!
//! Handles sending settlement messages via LayerZero protocol, monitoring verification,
//! and executing received messages on destination chains using batch processing.
//!
//! Key components:
//! - **LayerZeroSettler**: Main settler implementation
//! - **LayerZeroBatchProcessor**: Batches and executes settlements
//! - **Verification**: Monitors message verification across chains

use super::{SettlementError, Settler, SettlerId};
use crate::{
    interop::settler::layerzero::{
        contracts::{
            ILayerZeroEndpointV2::{self, PacketSent},
            ILayerZeroSettler, IReceiveUln302, MessagingParams,
        },
        types::{LayerZeroPacketInfo, LayerZeroPacketV1},
    },
    storage::{RelayStorage, StorageApi},
    transactions::{RelayTransaction, TransactionStatus, interop::InteropBundle},
    types::{Call3, IEscrow, LZChainConfigs, TransactionServiceHandles},
};
use alloy::{
    primitives::{Address, B256, Bytes, ChainId, U256, map::HashMap},
    providers::{DynProvider, Provider},
    rpc::types::{TransactionReceipt, TransactionRequest, state::AccountOverride},
    sol_types::{SolCall, SolEvent, SolValue},
};
use async_trait::async_trait;
use futures_util::future::{join_all, try_join_all};
use itertools::Itertools;
use std::time::Duration;
use tracing::{info, instrument};

/// LayerZero contract interfaces.
pub mod contracts;
/// LayerZero-specific types.
pub mod types;
pub use types::EndpointId;
/// Verification monitoring logic.
pub mod verification;
use verification::{LayerZeroVerificationMonitor, VerificationResult, is_message_available};
/// Layerzero batch processing.
pub mod batcher;
use batcher::{LayerZeroBatchProcessor, LayerZeroPoolHandle};

/// ULN config type constant
pub const ULN_CONFIG_TYPE: u32 = 2;

/// Layerzero configuration for a specific chain.
#[derive(Debug, Clone)]
pub struct LZChainConfig {
    /// LayerZero endpoint ID for this chain.
    pub endpoint_id: EndpointId,
    /// LayerZero endpoint address for this chain.
    pub endpoint_address: Address,
    /// Provider for this chain.
    pub provider: DynProvider,
    /// LayerZero settler contract address for this chain.
    pub settler_address: Address,
}

/// LayerZero settler implementation for cross-chain settlement attestation.
#[derive(Debug)]
pub struct LayerZeroSettler {
    /// Reverse mapping: endpoint ID to chain ID for efficient lookups.
    eid_to_chain: HashMap<EndpointId, ChainId>,
    /// Chain ID to LayerZero endpoint address mapping.
    endpoint_addresses: HashMap<ChainId, Address>,
    /// On-chain settler contract address.
    settler_address: Address,
    /// Storage backend for persisting data.
    storage: RelayStorage,
    /// Chain configurations.
    chain_configs: LZChainConfigs,
    /// Handle to the batch pool for processing settlements.
    settlement_pool: LayerZeroPoolHandle,
}

impl LayerZeroSettler {
    /// Creates a new LayerZero settler instance with batch processing.
    pub async fn new(
        endpoint_ids: HashMap<ChainId, EndpointId>,
        endpoint_addresses: HashMap<ChainId, Address>,
        providers: HashMap<ChainId, DynProvider>,
        settler_address: Address,
        storage: RelayStorage,
        tx_service_handles: TransactionServiceHandles,
    ) -> Result<Self, SettlementError> {
        // Build the reverse mapping for O(1) endpoint ID to chain ID lookups
        let eid_to_chain = endpoint_ids.iter().map(|(chain_id, eid)| (*eid, *chain_id)).collect();

        // Build chain configs
        let chain_configs =
            LZChainConfigs::new(&endpoint_ids, &endpoint_addresses, &providers, settler_address);

        // Create batch processor with pool
        let settlement_pool =
            LayerZeroBatchProcessor::run(chain_configs.clone(), tx_service_handles).await?;

        Ok(Self {
            eid_to_chain,
            endpoint_addresses,
            settler_address,
            storage,
            chain_configs,
            settlement_pool,
        })
    }

    /// Gets the LayerZero endpoint address for a given chain ID.
    pub fn get_endpoint_address(&self, chain_id: u64) -> Option<&Address> {
        self.endpoint_addresses.get(&chain_id)
    }

    /// Gets the cached chain configuration for a given chain ID.
    fn get_chain_config(&self, chain_id: u64) -> Result<&LZChainConfig, SettlementError> {
        self.chain_configs.get(&chain_id).ok_or_else(|| SettlementError::UnsupportedChain(chain_id))
    }

    /// Converts a LayerZero endpoint ID to a chain ID.
    fn eid_to_chain_id(&self, eid: EndpointId) -> Result<u64, SettlementError> {
        self.eid_to_chain.get(&eid).copied().ok_or_else(|| SettlementError::UnknownEndpointId(eid))
    }

    /// Extracts all packet information from a transaction receipt.
    async fn extract_packets_from_receipt(
        &self,
        receipt: &TransactionReceipt,
    ) -> Result<Vec<LayerZeroPacketInfo>, SettlementError> {
        let packets = try_join_all(
            receipt
                .inner
                .logs()
                .iter()
                .filter_map(|log| {
                    PacketSent::decode_raw_log(log.topics(), log.data().data.as_ref())
                        .ok()
                        .map(|ev| ev.encodedPayload)
                })
                .map(|encoded_payload| async move {
                    // Decode the packet from the encoded payload
                    let packet = LayerZeroPacketV1::decode(&encoded_payload)
                        .map_err(SettlementError::InternalError)?;

                    let src_chain_id = self.eid_to_chain_id(packet.src_eid)?;
                    let dst_chain_id = self.eid_to_chain_id(packet.dst_eid)?;

                    let receiver = packet.receiver_addr();

                    let dst_config = self.get_chain_config(dst_chain_id)?;
                    let src_config = self.get_chain_config(src_chain_id)?;

                    // Get the receive library address and ULN config of the dst_chain
                    // todo(joshie): unsure if in the future we can just assume that it's always
                    // the same. for now just fetch for each individual receiver in each chain.
                    let endpoint = ILayerZeroEndpointV2::new(
                        dst_config.endpoint_address,
                        &dst_config.provider,
                    );
                    let receive_lib_result =
                        endpoint.getReceiveLibrary(receiver, src_config.endpoint_id).call().await?;
                    let receive_lib_address = receive_lib_result.lib;

                    let receive_lib =
                        IReceiveUln302::new(receive_lib_address, &dst_config.provider);
                    let uln_config =
                        receive_lib.getUlnConfig(receiver, src_config.endpoint_id).call().await?;

                    Ok::<_, SettlementError>(LayerZeroPacketInfo::new(
                        packet,
                        src_chain_id,
                        dst_chain_id,
                        receive_lib_address,
                        uln_config,
                    ))
                }),
        )
        .await?;

        Ok(packets)
    }

    /// Extracts LayerZero packet information from settlement transaction receipts.
    ///
    /// This method parses transaction receipts to find `PacketSent` events emitted by
    /// LayerZero endpoints during the settlement sending phase. Each event contains
    /// the full packet information needed to track and execute the cross-chain message.
    async fn extract_packet_infos(
        &self,
        bundle: &InteropBundle,
    ) -> Result<Vec<LayerZeroPacketInfo>, SettlementError> {
        if bundle.settlement_txs.is_empty() {
            return Ok(vec![]);
        }

        info!(
            bundle_id = ?bundle.id,
            num_settlements = bundle.settlement_txs.len(),
            "Extracting LayerZero packet info from settlement receipts"
        );

        // Process each settlement transaction
        let packet_results = try_join_all(bundle.settlement_txs.iter().map(async |tx| {
            // Get transaction receipt from storage
            // Note: We can assume transactions are confirmed when called from SettlementsProcessing
            // state
            let (_, status) =
                self.storage.read_transaction_status(tx.id).await?.ok_or_else(|| {
                    SettlementError::InternalError("Transaction status not found".to_string())
                })?;

            let receipt = match status {
                TransactionStatus::Confirmed(receipt) => receipt,
                _ => unreachable!("we only process settlements if transactions are confirmed"),
            };

            // Extract packet info from receipt logs
            self.extract_packets_from_receipt(&receipt).await
        }))
        .await?;

        // Flatten all packet vectors into a single vector
        let packet_infos: Vec<LayerZeroPacketInfo> = packet_results.into_iter().flatten().collect();

        Ok(packet_infos)
    }
}

#[async_trait]
impl Settler for LayerZeroSettler {
    fn id(&self) -> SettlerId {
        SettlerId::LayerZero
    }

    fn address(&self) -> Address {
        self.settler_address
    }

    /// Builds a transaction to send settlement attestations to multiple destination chains via
    /// LayerZero.
    ///
    /// This method creates a single transaction that will send LayerZero messages to all specified
    /// source chains, notifying them about a settlement that occurred on the current chain. It will
    /// attach a msg.value to pay for the DVNs to attest to this event.
    #[instrument(skip(self), fields(settler_id = %self.id()))]
    async fn build_execute_send_transaction(
        &self,
        settlement_id: B256,
        current_chain_id: u64,
        source_chains: Vec<u64>,
        orchestrator: Address,
    ) -> Result<Option<RelayTransaction>, SettlementError> {
        let settler_context = self.encode_settler_context(source_chains.clone())?;

        let current_config = self.get_chain_config(current_chain_id)?;

        // Create endpoint contract instance
        let endpoint =
            ILayerZeroEndpointV2::new(current_config.endpoint_address, &current_config.provider);

        // Build multicall for fee quotes
        let mut multicall = current_config.provider.multicall().dynamic();

        for source_chain_id in &source_chains {
            let src_config = self.get_chain_config(*source_chain_id)?;

            let params = MessagingParams::new(
                *source_chain_id,
                src_config.endpoint_id,
                self.settler_address,
                settlement_id,
            );

            tracing::debug!(?params, "LayerZero quote params");

            multicall = multicall.add_dynamic(endpoint.quote(params, self.settler_address));
        }

        let quote_results = multicall.aggregate().await?;
        let native_lz_fee: U256 = quote_results.into_iter().map(|fee| fee.nativeFee).sum();

        tracing::debug!(?settlement_id, ?native_lz_fee, "Total LayerZero fee");

        let calldata = ILayerZeroSettler::executeSendCall {
            sender: orchestrator,
            settlementId: settlement_id,
            settlerContext: settler_context,
        }
        .abi_encode();

        // Create a transaction for the settlement with the calculated gas with native_lz_fee
        let from = Address::random();
        let tx_request = TransactionRequest::default()
            .from(from)
            .to(self.settler_address)
            .value(native_lz_fee)
            .input(calldata.clone().into());

        let gas_limit = current_config
            .provider
            .estimate_gas(tx_request)
            .account_override(from, AccountOverride::default().with_balance(U256::MAX))
            .await?;

        // Add 20% buffer to the gas estimate
        let gas_limit = gas_limit.saturating_mul(120).saturating_div(100);

        let tx = RelayTransaction::new_internal_with_value(
            self.settler_address,
            calldata,
            current_chain_id,
            gas_limit,
            native_lz_fee,
        );

        Ok(Some(tx))
    }

    fn encode_settler_context(
        &self,
        destination_chains: Vec<u64>,
    ) -> Result<Bytes, SettlementError> {
        let endpoint_ids: Vec<u32> = destination_chains
            .into_iter()
            .sorted()
            .map(|chain_id| self.get_chain_config(chain_id).map(|c| c.endpoint_id))
            .collect::<Result<Vec<_>, _>>()?;

        // Encode the endpoint IDs as a dynamic array of uint32
        Ok(endpoint_ids.abi_encode().into())
    }

    /// Waits for LayerZero messages to be verified on their destination chains.
    async fn wait_for_verifications(
        &self,
        bundle: &InteropBundle,
        timeout: Duration,
    ) -> Result<VerificationResult, SettlementError> {
        // Extract packet infos from bundle
        let packet_infos = self.extract_packet_infos(bundle).await?;
        LayerZeroVerificationMonitor::new(self.chain_configs.clone())
            .wait_for_verifications(packet_infos, timeout.as_secs())
            .await
    }

    /// Builds transactions to execute verified LayerZero messages on their destination chains.
    /// Always returns empty list - settlements handled internally via batch processor.
    async fn build_execute_receive_transactions(
        &self,
        bundle: &InteropBundle,
    ) -> Result<Vec<RelayTransaction>, SettlementError> {
        // Extract packet infos and filter for verified ones
        let all_packet_infos = self.extract_packet_infos(bundle).await?;

        if all_packet_infos.is_empty() {
            return Ok(vec![]);
        }

        // Check which packets are actually available for execute receive
        let availability_results: Vec<bool> = try_join_all(
            all_packet_infos.iter().map(|packet| is_message_available(packet, &self.chain_configs)),
        )
        .await?;

        // Filter packets based on availability results
        let packet_infos: Vec<LayerZeroPacketInfo> = all_packet_infos
            .into_iter()
            .zip(availability_results)
            .filter_map(|(packet, is_available)| if is_available { Some(packet) } else { None })
            .collect();

        info!(num_packets = packet_infos.len(), "Building LayerZero execute receive transactions");

        // Prepare all settlement data before sending
        let mut settlement_requests = Vec::with_capacity(packet_infos.len());
        for packet in packet_infos {
            // Get configs for source and destination chains
            let src_config = self.get_chain_config(packet.src_chain_id)?;
            let dst_config = self.get_chain_config(packet.dst_chain_id)?;

            // Build LayerZero receive call
            let lz_receive_call = packet.build_lz_receive_call(src_config.endpoint_id);

            // Get escrow information
            let settlement_id = packet.settlement_id().map_err(SettlementError::InternalError)?;
            let escrow_info = bundle.get_escrows(packet.dst_chain_id, settlement_id)?;

            // Build multicall
            let calls = build_multicall_calls(
                &packet,
                &lz_receive_call,
                dst_config.endpoint_address,
                &escrow_info.escrow_ids,
                escrow_info.escrow_address,
            )?;

            settlement_requests.push((
                packet.dst_chain_id,
                src_config.endpoint_id,
                packet.nonce,
                calls,
            ));
        }

        // Send all settlements to the pool
        let futures = settlement_requests.into_iter().map(|(chain_id, src_eid, nonce, calls)| {
            let settlement_pool = self.settlement_pool.clone();
            async move {
                settlement_pool
                    .send_settlement_and_wait(chain_id, src_eid, nonce, calls)
                    .await
                    .map_err(|e| {
                        SettlementError::InternalError(format!("Settlement pool error: {e:?}"))
                    })
            }
        });
        let results = join_all(futures).await;

        // Check if any failed
        let mut any_failed = false;
        for result in &results {
            if let Err(e) = result {
                tracing::error!("Failed to process packet: {:?}", e);
                any_failed = true;
            }
        }

        // Return error if any packet failed
        if any_failed {
            return Err(SettlementError::InternalError(
                "One or more packets failed to process".to_string(),
            ));
        }

        // Always return empty - batch processor handles execution
        Ok(vec![])
    }
}

/// Builds the multicall calls for executing LayerZero receive and escrow settlement.
///
/// This function creates calls that:
/// 1. Commit the verification by calling ReceiveLib.commitVerification
/// 2. Execute lzReceive to process the cross-chain message
/// 3. Settle the escrows to release funds
fn build_multicall_calls(
    packet: &LayerZeroPacketInfo,
    lz_receive_call: &ILayerZeroEndpointV2::lzReceiveCall,
    endpoint_address: Address,
    escrow_ids: &[B256],
    escrow_address: Address,
) -> Result<Vec<Call3>, SettlementError> {
    let commit_verification_calldata = contracts::IReceiveUln302::commitVerificationCall {
        _packetHeader: packet.packet_header.clone().into(),
        _payloadHash: packet.payload_hash,
    }
    .abi_encode();

    // Encode the LayerZero receive call
    let lz_receive_calldata = lz_receive_call.abi_encode();

    // Encode the escrow settle call
    let settle_calldata = IEscrow::settleCall { escrowIds: escrow_ids.to_vec() }.abi_encode();

    // Build the calls with the correct order:
    // 1. commitVerification
    // 2. lzReceive
    // 3. settle
    let calls = vec![
        Call3 {
            target: packet.receive_lib_address,
            allowFailure: false,
            callData: commit_verification_calldata.into(),
        },
        Call3 {
            target: endpoint_address,
            allowFailure: false,
            callData: lz_receive_calldata.into(),
        },
        Call3 { target: escrow_address, allowFailure: false, callData: settle_calldata.into() },
    ];

    Ok(calls)
}
