create table if not exists locked_liquidity (
    chain_id bigint not null,
    asset_address bytea not null,
    amount numeric not null default 0,
    primary key (chain_id, asset_address)
);

create table if not exists pending_unlocks (
    chain_id bigint not null,
    asset_address bytea not null,
    block_number bigint not null,
    amount numeric not null,
    primary key (chain_id, asset_address)
);