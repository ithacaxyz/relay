-- Create table for tracking pending refunds
-- Stores bundle_id and the maximum refund timestamp for delayed refund processing
-- This table is used by the RefundMonitorService to find refunds ready for execution
-- NOTE: No foreign key constraint to pending_bundles as bundles may move to finished_bundles
CREATE TABLE pending_refunds (
    bundle_id BYTEA PRIMARY KEY,
    refund_timestamp TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for efficiently finding refunds ready to process
CREATE INDEX idx_pending_refunds_timestamp 
    ON pending_refunds(refund_timestamp);

-- Add new bundle status values
ALTER TYPE bundle_status ADD VALUE 'settlements_queued';
ALTER TYPE bundle_status ADD VALUE 'settlements_confirmed';
ALTER TYPE bundle_status ADD VALUE 'refunds_scheduled';
ALTER TYPE bundle_status ADD VALUE 'refunds_ready';
