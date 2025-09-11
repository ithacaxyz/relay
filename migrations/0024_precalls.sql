create table if not exists precalls (
    address bytea not null,
    chain_id bigint not null,
    nonce bytea not null,
    data jsonb not null,
    primary key (address, chain_id, nonce)
);

-- Index for efficient queries
CREATE INDEX idx_precalls_address ON precalls(address);
