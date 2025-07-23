-- create enum for pull_gas transaction states
CREATE TYPE pull_gas_state AS ENUM ('pending', 'completed', 'failed');

-- create table to track pull_gas transactions with JSONB storage
CREATE TABLE IF NOT EXISTS pull_gas_transactions (
    -- transaction hash
    id BYTEA PRIMARY KEY,
    -- signer address
    signer_address BYTEA NOT NULL,
    -- chain ID
    chain_id BIGINT NOT NULL,
    state pull_gas_state NOT NULL DEFAULT 'pending',
    -- tx envelope
    transaction_data JSONB NOT NULL,
    -- timestamps
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- add indexes for queries
CREATE INDEX idx_pull_gas_signer_chain ON pull_gas_transactions(signer_address, chain_id);
CREATE INDEX idx_pull_gas_state ON pull_gas_transactions(state);