update pending_txs set tx = jsonb_set(tx, '{quote,intent,encodedPreCalls}', tx#>'{quote,intent,encodedPreOps}') - '{quote,intent,encodedPreOps}';
update queued_txs set tx = jsonb_set(tx, '{quote,intent,encodedPreCalls}', tx#>'{quote,intent,encodedPreOps}') - '{quote,intent,encodedPreOps}';
update pending_txs set tx = jsonb_set(tx, '{quote,intent,supportedAccountImplementation}', tx#>'{quote,intent,supportedDelegationImplementation}') - '{quote,intent,supportedDelegationImplementation}';
update queued_txs set tx = jsonb_set(tx, '{quote,intent,supportedAccountImplementation}', tx#>'{quote,intent,supportedDelegationImplementation}') - '{quote,intent,supportedDelegationImplementation}';
