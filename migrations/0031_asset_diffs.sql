-- Create table for storing asset diffs from confirmed transactions
create table asset_diffs (
    tx_id bytea not null primary key references txs(tx_id) on delete cascade,
    asset_diffs jsonb not null,
    created_at timestamptz not null default now()
);
