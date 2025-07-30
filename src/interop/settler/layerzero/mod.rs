//! # LayerZero Protocol Integration
//!
//! This module implements the LayerZero settler for cross-chain settlement attestation in the
//! Ithaca Relay. LayerZero is an omnichain interoperability protocol that enables secure message
//! passing between blockchains.
//!
//! ## Overview
//!
//! The LayerZero integration allows the relay to:
//! - Send cross-chain settlement attestations via LayerZero's messaging protocol
//! - Monitor and verify message delivery across chains
//! - Execute received messages to complete settlement flows
//!
//! ## Cross-Chain Settlement Flow
//!
//! 1. **Settlement Initiation**: When a settlement needs to be attested across chains, the relay
//!    calls `build_execute_send_transaction` to create a transaction that sends LayerZero messages
//!    to all destination chains.
//!
//! 2. **Message Transmission**: The LayerZero endpoint on the source chain emits `PacketSent`
//!    events containing the encoded message payload and routing information.
//!
//! 3. **Off-Chain Verification**: LayerZero's decentralized verifier network (DVNs) observes the
//!    source chain event and attests to its validity on the destination chains.
//!
//! 4. **Message Availability**: Once verified, the message becomes available on the destination
//!    chain's LayerZero endpoint, indicated by a non-zero `inboundPayloadHash`.
//!
//! 5. **Message Execution**: The relay monitors for message verification and builds `lzReceive`
//!    transactions to execute the delivered messages on each destination chain.
//!
//! ## Key Concepts
//!
//! - **Endpoint ID (EID)**: Each blockchain in the LayerZero network has a unique endpoint ID
//! - **GUID**: Globally Unique Identifier for each LayerZero packet
//! - **Nonce**: Per-sender ordering mechanism to ensure message sequencing
//! - **DVN**: Decentralized Verifier Network that attests to cross-chain messages
//! - **Packet**: The unit of cross-chain communication containing routing info and payload

use super::{SettlementError, Settler, SettlerId};
use crate::{
    interop::settler::layerzero::{
        contracts::{
            ILayerZeroEndpointV2::{self, PacketSent, lzReceiveCall},
            ILayerZeroSettler,
            IReceiveUln302::{self, commitVerificationCall},
            MessagingParams,
        },
        types::{LayerZeroPacketInfo, LayerZeroPacketV1},
    },
    storage::{RelayStorage, StorageApi},
    transactions::{RelayTransaction, TransactionStatus, interop::InteropBundle},
    types::{
        Call3,
        IEscrow::{self, settleCall},
        aggregate3Call,
        rpc::BundleId,
    },
};
use alloy::{
    primitives::{Address, B256, Bytes, ChainId, U256, map::HashMap},
    providers::{CallItem, DynProvider, MULTICALL3_ADDRESS, Provider},
    rpc::types::{TransactionReceipt, TransactionRequest, state::AccountOverride},
    sol_types::{SolCall, SolEvent, SolValue},
};
use async_trait::async_trait;
use futures_util::future::try_join_all;
use itertools::Itertools;
use std::{sync::Arc, time::Duration};
use tracing::{debug, info, instrument};

/// LayerZero contract interfaces.
pub mod contracts;
/// LayerZero-specific types.
pub mod types;
pub use types::EndpointId;
/// Verification monitoring logic.
pub mod verification;
use verification::{LayerZeroVerificationMonitor, VerificationResult, is_message_available};

/// ULN config type constant
pub const ULN_CONFIG_TYPE: u32 = 2;

/// Layerzero configuration for a specific chain.
#[derive(Debug, Clone)]
pub(super) struct LZChainConfig {
    /// LayerZero endpoint ID for this chain.
    pub endpoint_id: EndpointId,
    /// LayerZero endpoint address for this chain.
    pub endpoint_address: Address,
    /// Provider for this chain.
    pub provider: DynProvider,
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
    chain_configs: Arc<HashMap<ChainId, LZChainConfig>>,
}

impl LayerZeroSettler {
    /// Creates a new LayerZero settler instance for cross-chain settlement attestation.
    pub fn new(
        endpoint_ids: HashMap<ChainId, EndpointId>,
        endpoint_addresses: HashMap<ChainId, Address>,
        providers: HashMap<ChainId, DynProvider>,
        settler_address: Address,
        storage: RelayStorage,
    ) -> Self {
        // Build the reverse mapping for O(1) endpoint ID to chain ID lookups
        let eid_to_chain = endpoint_ids.iter().map(|(chain_id, eid)| (*eid, *chain_id)).collect();

        // Build chain configs
        let chain_configs = endpoint_ids
            .keys()
            .filter_map(|chain_id| {
                let endpoint_id = endpoint_ids.get(chain_id)?;
                let endpoint_address = endpoint_addresses.get(chain_id)?;
                let provider = providers.get(chain_id)?;

                Some((
                    *chain_id,
                    LZChainConfig {
                        endpoint_id: *endpoint_id,
                        endpoint_address: *endpoint_address,
                        provider: provider.clone(),
                    },
                ))
            })
            .collect();

        Self {
            eid_to_chain,
            endpoint_addresses,
            settler_address,
            storage,
            chain_configs: Arc::new(chain_configs),
        }
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

    /// Estimates gas for the receive transaction. If it fails, it runs the multicall again to fetch
    /// and log the errors.
    async fn estimate_receive_transaction_gas(
        &self,
        calls: &[Call3; 3],
        provider: &DynProvider,
        bundle_id: BundleId,
    ) -> Result<u64, SettlementError> {
        let multicall_calldata = aggregate3Call { calls: calls.to_vec() }.abi_encode();
        let tx_request =
            TransactionRequest::default().to(MULTICALL3_ADDRESS).input(multicall_calldata.into());

        let result = provider.estimate_gas(tx_request).await;

        let Err(e) = result else {
            return result.map_err(Into::into);
        };

        let (commit_verification, lz_receive, settle) = provider
            .multicall()
            .add_call::<commitVerificationCall>(
                CallItem::new(calls[0].target, calls[0].callData.clone()).allow_failure(true),
            )
            .add_call::<lzReceiveCall>(
                CallItem::new(calls[1].target, calls[1].callData.clone()).allow_failure(true),
            )
            .add_call::<settleCall>(
                CallItem::new(calls[2].target, calls[2].callData.clone()).allow_failure(true),
            )
            .aggregate3()
            .await?;

        if commit_verification.is_err() {
            tracing::error!(?bundle_id, "commitVerification failed: {:?}", commit_verification);
        } else if lz_receive.is_err() {
            tracing::error!(?bundle_id, "lzReceive failed: {:?}", lz_receive);
        } else if settle.is_err() {
            tracing::error!(?bundle_id, "settle failed: {:?}", settle);
        } else {
            tracing::error!(?bundle_id, "all calls would succeed but gas estimation still failed");
        }

        Err(SettlementError::InternalError(format!("Gas estimation failed: {e:?}")))
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

                    let receiver = Address::from_slice(&packet.receiver[12..]);

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

    /// Builds a transaction to execute a single verified LayerZero message.
    ///
    /// This method constructs a multicall transaction that:
    /// 1. Calls `lzReceive` to complete the LayerZero message delivery
    /// 2. Calls `Escrow.settle` to release the escrowed funds
    ///
    /// ## Note
    ///
    /// This method assumes the message has already been verified. Always check
    /// `is_message_available` before building the execute transaction.
    async fn build_execute_receive_transaction(
        &self,
        packet: &LayerZeroPacketInfo,
        bundle: &InteropBundle,
    ) -> Result<RelayTransaction, SettlementError> {
        debug!(
            packet_guid = ?packet.guid,
            dst_chain = packet.dst_chain_id,
            "Building multicall execute receive transaction"
        );

        let dst_config = self.get_chain_config(packet.dst_chain_id)?;
        let src_config = self.get_chain_config(packet.src_chain_id)?;

        // Build the LayerZero receive call
        let lz_receive_call = packet.build_lz_receive_call(src_config.endpoint_id);

        // Extract and filter escrows for this settlement
        let settlement_id = packet.settlement_id().map_err(SettlementError::InternalError)?;
        let escrow_info = bundle.get_escrows(packet.dst_chain_id, settlement_id)?;

        // Wait for the correct nonce before proceeding.
        let endpoint = ILayerZeroEndpointV2::new(dst_config.endpoint_address, &dst_config.provider);
        let sender = B256::left_padding_from(packet.sender.as_slice());
        loop {
            let current_nonce = endpoint
                .inboundNonce(packet.receiver, src_config.endpoint_id, sender)
                .call()
                .await?;

            let expected_nonce = current_nonce + 1;

            tracing::debug!(
                bundle_id = ?bundle.id,
                packet_nonce = packet.nonce,
                current_inbound_nonce = current_nonce,
                expected_nonce = expected_nonce,
                "Nonce check"
            );

            if packet.nonce == expected_nonce {
                break;
            }

            tracing::info!(
                bundle_id = ?bundle.id,
                packet_nonce = packet.nonce,
                expected_nonce = expected_nonce,
                "Waiting for earlier nonces to be processed"
            );

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        let calls = build_multicall_calls(
            packet,
            &lz_receive_call,
            dst_config.endpoint_address,
            &escrow_info.escrow_ids,
            escrow_info.escrow_address,
        );

        tracing::debug!(bundle_id = ?bundle.id, "Estimating multicall for packet {:?}", &packet);
        let gas_limit =
            self.estimate_receive_transaction_gas(&calls, &dst_config.provider, bundle.id).await?;

        let tx = RelayTransaction::new_internal(
            MULTICALL3_ADDRESS,
            aggregate3Call { calls: calls.to_vec() }.abi_encode(),
            packet.dst_chain_id,
            gas_limit,
        );

        debug!(
            packet_guid = ?packet.guid,
            dst_chain = packet.dst_chain_id,
            num_escrows = escrow_info.escrow_ids.len(),
            gas_limit = gas_limit,
            "Built multicall execute receive transaction"
        );

        Ok(tx)
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
    ///
    /// This method monitors the verification status of all LayerZero packets sent as part of
    /// the settlement process. It uses both event monitoring (via WebSocket when available)
    /// and polling fallbacks to track when messages become available for execution.
    ///
    /// # Verification Process
    ///
    /// 1. Extracts packet information from settlement transaction receipts
    /// 2. Groups packets by destination chain for efficient monitoring
    /// 3. Sets up event subscriptions for `PacketVerified` events.
    /// 4. Falls back to polling `inboundPayloadHash` for chains without WebSocket
    /// 5. Returns early if all messages are already verified
    ///
    /// ```
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
    ///
    /// This method creates `lzReceive` transactions for all verified messages, allowing the
    /// destination chain contracts to process the settlement attestations.
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
            all_packet_infos
                .iter()
                .map(async |packet| is_message_available(packet, &self.chain_configs).await),
        )
        .await?;

        // Filter packets based on availability results
        let packet_infos: Vec<LayerZeroPacketInfo> = all_packet_infos
            .into_iter()
            .zip(availability_results)
            .filter_map(|(packet, is_available)| if is_available { Some(packet) } else { None })
            .collect();

        info!(num_packets = packet_infos.len(), "Building LayerZero execute receive transactions");

        // Build execute receive transactions
        let execute_receive_txs = try_join_all(
            packet_infos
                .iter()
                .map(|packet| self.build_execute_receive_transaction(packet, bundle)),
        )
        .await?;

        info!(
            num_deliveries = execute_receive_txs.len(),
            "Successfully built execute receive transactions"
        );

        Ok(execute_receive_txs)
    }
}

/// Builds the multicall data for executing LayerZero receive and escrow settlement.
///
/// This function creates a multicall that:
/// 1. Commits the verification by calling ReceiveLib.commitVerification
/// 2. Executes lzReceive to process the cross-chain message
/// 3. Settles the escrows to release funds
fn build_multicall_calls(
    packet: &LayerZeroPacketInfo,
    lz_receive_call: &ILayerZeroEndpointV2::lzReceiveCall,
    endpoint_address: Address,
    escrow_ids: &[B256],
    escrow_address: Address,
) -> [Call3; 3] {
    [
        Call3 {
            target: packet.receive_lib_address,
            allowFailure: false,
            callData: contracts::IReceiveUln302::commitVerificationCall {
                _packetHeader: packet.packet_header.clone().into(),
                _payloadHash: packet.payload_hash,
            }
            .abi_encode()
            .into(),
        },
        Call3 {
            target: endpoint_address,
            allowFailure: false,
            callData: lz_receive_call.abi_encode().into(),
        },
        Call3 {
            target: escrow_address,
            allowFailure: false,
            callData: IEscrow::settleCall { escrowIds: escrow_ids.to_vec() }.abi_encode().into(),
        },
    ]
}
