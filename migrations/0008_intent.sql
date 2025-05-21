update pending_txs set tx = jsonb_set(tx, '{quote,intent}', tx#>'{quote,op}') - '{quote,op}';
update queued_txs set tx = jsonb_set(tx, '{quote,intent}', tx#>'{quote,op}') - '{quote,op}';
