create type bridge_transfer_status as enum ('pending', 'sent', 'outbound_failed', 'completed', 'inbound_failed');

create table if not exists bridge_transfers (
    transfer_id bytea not null unique,
    transfer_data jsonb not null,
    bridge_data jsonb,
    outbound_block_number bigint,
    inbound_block_number bigint,
    status bridge_transfer_status not null default 'pending'
);
