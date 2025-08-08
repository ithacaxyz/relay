create index if not exists accounts_address on accounts (address);

create index if not exists keys_account_address on keys (account_address);

create index if not exists txs_bundle_id on txs (bundle_id);

create index if not exists txs_tx_id on txs (tx_id);
