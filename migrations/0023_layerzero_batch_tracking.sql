-- LayerZero nonce tracking table
CREATE TABLE layerzero_nonces (
    chain_id BIGINT NOT NULL,
    src_eid INTEGER NOT NULL,
    nonce_lz BIGINT NOT NULL,
    tx_id BYTEA NOT NULL, -- 32 bytes
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (chain_id, src_eid)
);

-- Index for efficient queries
CREATE INDEX idx_layerzero_nonces_tx_id ON layerzero_nonces(tx_id);