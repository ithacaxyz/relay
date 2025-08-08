alter table pending_txs rename column envelope to envelopes;
update pending_txs set envelopes = jsonb_build_array(envelopes);
