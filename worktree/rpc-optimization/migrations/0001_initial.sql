create table if not exists accounts (
    address bytea not null unique,
    account jsonb not null,
    created_at timestamp not null default now ()
);

create table if not exists keys (
    key_id bytea not null,
    account_address bytea not null,
    key_hash bytea not null,
    signature bytea not null
);

create type tx_status as enum ('inflight', 'pending', 'confirmed', 'failed');

create table if not exists txs (
    tx_id bytea not null unique,
    bundle_id bytea not null,
    status tx_status not null default 'inflight',
    tx_hash bytea
);

create table if not exists pending_txs (
    chain_id bigserial not null,
    sender bytea not null,
    tx_id bytea not null unique,
    tx jsonb not null,
    envelope jsonb not null,
    received_at timestamp not null
);
