update pending_txs set tx = jsonb_set(tx, '{quote,orchestrator}', tx#>'{quote,entrypoint}') - '{quote,entrypoint}';
update queued_txs set tx = jsonb_set(tx, '{quote,orchestrator}', tx#>'{quote,entrypoint}') - '{quote,entrypoint}';
