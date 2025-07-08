//! Refund monitoring service for processing pending escrow refunds.
//!
//! This service continuously monitors for escrow refunds that have reached their
//! refund timestamp and resumes the interop flow to process them.

use crate::{
    error::StorageError,
    storage::{RelayStorage, StorageApi},
    transactions::interop::{BundleStatus, InteropServiceHandle},
    types::rpc::BundleId,
};
use chrono::Utc;
use std::time::Duration;
use tokio::time::interval;
use tracing::{error, info, instrument};

/// Default interval between refund checks (60 seconds).
const DEFAULT_CHECK_INTERVAL_SECS: u64 = 60;

/// Service that monitors and processes pending refunds.
#[derive(Debug)]
pub struct RefundMonitorService {
    /// Storage backend for querying pending refunds.
    storage: RelayStorage,
    /// Handle to the interop service for resuming bundle processing.
    interop_service: InteropServiceHandle,
    /// Interval between refund checks (default: 60 seconds).
    check_interval: Duration,
}

impl RefundMonitorService {
    /// Creates a new refund monitor service with default interval.
    pub fn new(storage: RelayStorage, interop_service: InteropServiceHandle) -> Self {
        Self {
            storage,
            interop_service,
            check_interval: Duration::from_secs(DEFAULT_CHECK_INTERVAL_SECS),
        }
    }

    /// Creates a new refund monitor service with a custom check interval.
    pub fn with_interval(
        storage: RelayStorage,
        interop_service: InteropServiceHandle,
        check_interval: Duration,
    ) -> Self {
        Self {
            storage,
            interop_service,
            check_interval,
        }
    }

    /// Runs the refund monitoring loop.
    ///
    /// This method will run indefinitely, periodically checking for refunds
    /// that are ready to be processed and resuming their bundle processing.
    #[instrument(skip(self), fields(service = "refund_monitor"))]
    pub async fn run(self) -> Result<(), StorageError> {
        info!("Starting refund monitor service");
        let mut check_timer = interval(self.check_interval);

        loop {
            check_timer.tick().await;

            if let Err(e) = self.process_pending_refunds().await {
                error!("Error processing pending refunds: {e}");
            }
        }
    }

    /// Processes all pending refunds that are ready.
    #[instrument(skip(self), fields(service = "refund_monitor"))]
    async fn process_pending_refunds(&self) -> Result<(), StorageError> {
        let current_time = Utc::now();
        let pending_refunds = self.storage.get_pending_refunds_ready(current_time).await?;

        if pending_refunds.is_empty() {
            return Ok(());
        }

        info!(
            count = pending_refunds.len(),
            current_time = ?current_time,
            "Found pending refunds ready to process"
        );

        for (bundle_id, refund_timestamp) in pending_refunds {
            info!(
                bundle_id = ?bundle_id,
                refund_timestamp = ?refund_timestamp,
                "Processing refund for bundle"
            );

            // Resume the bundle processing in the interop service
            // The interop service will handle the actual refund transactions
            if let Err(e) = self.resume_bundle_for_refund(bundle_id).await {
                error!(
                    bundle_id = ?bundle_id,
                    error = ?e,
                    "Failed to resume bundle for refund"
                );
            }
        }

        Ok(())
    }

    /// Resumes bundle processing for refund.
    ///
    /// Transitions a bundle from waiting state to refund-ready after its refund timestamp
    /// is reached, triggering the interop service to execute refund transactions that
    /// return escrowed assets to users.
    async fn resume_bundle_for_refund(&self, bundle_id: BundleId) -> Result<(), StorageError> {
        // Get the bundle from storage
        if let Some(mut bundle_with_status) = self.storage.get_pending_bundle(bundle_id).await? {
            self.storage.mark_refund_ready(bundle_id, BundleStatus::RefundsReady).await?;

            // Update the local bundle status to match
            bundle_with_status.status = BundleStatus::RefundsReady;

            // Send the bundle to the interop service for processing
            self.interop_service.send_bundle_with_status(bundle_with_status);
            Ok(())
        } else {
            // Log error but don't fail - the bundle might have been processed elsewhere
            error!(
                bundle_id = ?bundle_id,
                "Bundle not found in storage when processing refund"
            );
            // Still remove the refund to avoid repeated attempts on missing bundles
            self.storage.remove_processed_refund(bundle_id).await?;
            Ok(())
        }
    }

    /// Spawns the refund monitor service as a background task.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(e) = self.run().await {
                error!("Refund monitor service exited with error: {e}");
            }
        })
    }
}
