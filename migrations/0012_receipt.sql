delete from txs where status = 'confirmed';
alter table txs add column receipt jsonb;