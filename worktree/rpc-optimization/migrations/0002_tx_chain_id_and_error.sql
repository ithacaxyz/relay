alter table txs
add column chain_id bigserial not null,
add column error text;
