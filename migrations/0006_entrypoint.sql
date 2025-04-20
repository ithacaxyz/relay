update pending_txs set tx = jsonb_set(tx, '{quote,entrypoint}', tx->'entrypoint') - 'entrypoint';
update queued_txs set tx = jsonb_set(tx, '{quote,entrypoint}', tx->'entrypoint') - 'entrypoint';
