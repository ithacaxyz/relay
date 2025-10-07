-- Add indexes for wallet_getCallsHistory endpoint
-- Multi-chain bundle indexes (JSONB-based)
-- GIN index on bundle_data to enable efficient address lookups in dst_txs
CREATE INDEX IF NOT EXISTS idx_pending_bundles_dst_txs ON pending_bundles
  USING gin ((bundle_data->'dst_txs'));

CREATE INDEX IF NOT EXISTS idx_finished_bundles_dst_txs ON finished_bundles
  USING gin ((bundle_data->'dst_txs'));

-- Timestamp indexes for multi-chain bundles
CREATE INDEX IF NOT EXISTS idx_finished_bundles_finished_at_desc ON finished_bundles (finished_at DESC);
CREATE INDEX IF NOT EXISTS idx_pending_bundles_created_at_desc ON pending_bundles (created_at DESC);

-- Single-chain bundle indexes (transaction-based)
-- GIN index on queued_txs.tx JSONB for EOA extraction
CREATE INDEX IF NOT EXISTS idx_queued_txs_eoa ON queued_txs
  USING gin ((tx->'kind'->'quote'->'intent'));

CREATE INDEX IF NOT EXISTS idx_pending_txs_eoa ON pending_txs
  USING gin ((tx->'kind'->'quote'->'intent'));

-- Composite index for bundle_transactions queries
CREATE INDEX IF NOT EXISTS idx_bundle_transactions_tx_id ON bundle_transactions(tx_id);
CREATE INDEX IF NOT EXISTS idx_bundle_transactions_bundle_id ON bundle_transactions(bundle_id);
