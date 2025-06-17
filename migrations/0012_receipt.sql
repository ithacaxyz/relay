DELETE FROM txs WHERE status = 'confirmed';
ALTER TABLE txs ADD COLUMN receipt jsonb;