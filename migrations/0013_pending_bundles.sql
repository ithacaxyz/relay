-- Collapsed migrations 0013-0017: Pending bundles table and related functionality
-- This migration combines all bundle-related changes into a single migration

-- Create bundle status enum with all final values
CREATE TYPE bundle_status AS ENUM (
    'init',
    'source_queued',
    'source_confirmed',
    'source_failures',
    'destination_pending',
    'destination_failures',
    'destination_confirmed',
    'refunds_queued',
    'withdrawals_queued',
    'done',
    'failed'
);

-- Stores pending interop bundles for crash recovery
CREATE TABLE pending_bundles (
    bundle_id BYTEA PRIMARY KEY,
    status bundle_status NOT NULL,
    bundle_data JSONB NOT NULL,  -- Stores serialized bundle data
    quote_signer TEXT,  -- Tracks which relay owns each bundle
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP
);

-- Create indexes for efficient queries
CREATE INDEX idx_pending_bundles_created_at ON pending_bundles(created_at);
CREATE INDEX idx_pending_bundles_data ON pending_bundles USING gin(bundle_data);
CREATE INDEX idx_pending_bundles_quote_signer ON pending_bundles(quote_signer);

-- Stores finished interop bundles for historical tracking
CREATE TABLE finished_bundles (
    bundle_id BYTEA PRIMARY KEY,
    status bundle_status NOT NULL,
    bundle_data JSONB NOT NULL,  -- Stores serialized bundle data
    quote_signer TEXT,  -- Tracks which relay owned each bundle
    created_at TIMESTAMP NOT NULL,
    finished_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Create indexes for efficient queries on finished bundles
CREATE INDEX idx_finished_bundles_finished_at ON finished_bundles(finished_at);
CREATE INDEX idx_finished_bundles_status ON finished_bundles(status);
CREATE INDEX idx_finished_bundles_quote_signer ON finished_bundles(quote_signer);