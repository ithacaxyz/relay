create table bundle_transactions (
    bundle_id bytea not null,
    tx_id bytea not null
);

insert into bundle_transactions (bundle_id, tx_id) select bundle_id, tx_id from txs;

alter table txs drop column bundle_id;