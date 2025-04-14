create table if not exists queued_txs (
    id serial primary key,
    chain_id bigserial not null,
    tx_id bytea not null unique,
    tx jsonb not null
);
