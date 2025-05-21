update pending_txs set tx = jsonb_set(tx, '{quote,orchestrator}', tx->'orchestrator') - 'orchestrator';
update queued_txs set tx = jsonb_set(tx, '{quote,orchestrator}', tx->'orchestrator') - 'orchestrator';
