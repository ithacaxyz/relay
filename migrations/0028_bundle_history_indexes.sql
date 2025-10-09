-- Add support for wallet_getCallsHistory endpoint

-- Add tx column to txs table for history queries
-- NULL for interop bundles (data in bundle_data), populated for single-chain
alter table txs add column tx jsonb;

-- Create immutable function to extract received_at timestamp from tx JSONB
-- This is needed for indexing since ::timestamptz cast is not immutable
create or replace function tx_received_at_immutable(tx jsonb)
returns timestamptz
language sql
immutable
parallel safe
return (tx->>'received_at')::timestamptz;

-- Multi-chain bundle composite indexes (EOA + timestamp)
-- These enable index-only scans and early stop on ORDER BY ... LIMIT
-- Note: dst_txs is typically a single-element array, so we index the first element's EOA
create index if not exists idx_pending_bundles_eoa_created_at
  on pending_bundles ((bundle_data->'dst_txs'->0->'quote'->'intent'->>'eoa'), created_at desc);
create index if not exists idx_finished_bundles_eoa_finished_at
  on finished_bundles ((bundle_data->'dst_txs'->0->'quote'->'intent'->>'eoa'), finished_at desc);

-- Single-chain bundle composite index (EOA + timestamp)
-- Partial index only on non-null tx for single-chain bundle queries
create index if not exists idx_txs_eoa_received_at
  on txs (
    (tx->'quote'->'intent'->>'eoa'),
    tx_received_at_immutable(tx) desc
  )
  where tx is not null;

-- Bundle-transaction mapping indexes
-- Composite index for joins and lookups
create index if not exists idx_bundle_transactions_composite
  on bundle_transactions(bundle_id, tx_id);
create index if not exists idx_bundle_transactions_tx_id
  on bundle_transactions(tx_id);
