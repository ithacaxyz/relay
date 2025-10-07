-- Add support for wallet_getCallsHistory endpoint

-- Add tx column to txs table for history queries
-- NULL for interop bundles (data in bundle_data), populated for single-chain
alter table txs add column tx jsonb;

-- Multi-chain bundle indexes
-- Note: dst_txs is typically a single-element array, so we index the first element's EOA
-- This is more efficient than a GIN index on the entire array
create index if not exists idx_pending_bundles_dst_txs_eoa
  on pending_bundles ((bundle_data->'dst_txs'->0->'quote'->'intent'->>'eoa'));
create index if not exists idx_finished_bundles_dst_txs_eoa
  on finished_bundles ((bundle_data->'dst_txs'->0->'quote'->'intent'->>'eoa'));

-- Timestamp indexes for sorting
create index if not exists idx_pending_bundles_created_at
  on pending_bundles (created_at desc);
create index if not exists idx_finished_bundles_finished_at
  on finished_bundles (finished_at desc);

-- Single-chain bundle indexes
-- B-tree index for EOA text lookups (queries use ->> for text extraction)
create index if not exists idx_txs_tx_eoa
  on txs ((tx->'quote'->'intent'->>'eoa'));

-- Partial index for non-null tx (covers "WHERE tx IS NOT NULL" queries)
create index if not exists idx_txs_tx_not_null
  on txs (tx_id) where tx is not null;

-- Bundle-transaction mapping indexes
-- Composite index for LEFT JOIN + WHERE clause optimization
create index if not exists idx_bundle_transactions_composite
  on bundle_transactions(bundle_id, tx_id);
create index if not exists idx_bundle_transactions_tx_id
  on bundle_transactions(tx_id);
