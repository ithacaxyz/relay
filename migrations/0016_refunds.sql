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

-- Update bundle_status enum to add new statuses and remove withdrawals_queued
-- Since PostgreSQL doesn't allow modifying enums directly, we need to recreate it
CREATE TYPE bundle_status_new AS ENUM (
    'init',
    'source_queued',
    'source_confirmed',
    'source_failures',
    'destination_queued',
    'destination_failures',
    'destination_confirmed',
    'refunds_queued',
    'done',
    'failed',
    'settlements_queued',
    'settlements_confirmed',
    'refunds_scheduled',
    'refunds_ready'
);

-- Update pending_bundles table
ALTER TABLE pending_bundles 
    ALTER COLUMN status TYPE bundle_status_new 
    USING status::text::bundle_status_new;

-- Update finished_bundles table
ALTER TABLE finished_bundles 
    ALTER COLUMN status TYPE bundle_status_new 
    USING status::text::bundle_status_new;

-- Drop old enum
DROP TYPE bundle_status;

-- Rename new enum to original name
ALTER TYPE bundle_status_new RENAME TO bundle_status;