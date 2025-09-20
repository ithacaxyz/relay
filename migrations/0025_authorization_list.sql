-- Migrate from authorization (single optional) to authorization_list (array) in Intent variant

-- For pending_txs: rename authorization to authorization_list and convert to array
UPDATE pending_txs 
SET tx = jsonb_set(
    tx - 'authorization',
    '{authorization_list}',
    CASE
        WHEN tx->'authorization' IS NOT NULL AND tx->'authorization' != 'null'::jsonb THEN
            jsonb_build_array(tx->'authorization')
        ELSE
            '[]'::jsonb
    END
)
WHERE tx ? 'quote';

-- For queued_txs: rename authorization to authorization_list and convert to array
UPDATE queued_txs
SET tx = jsonb_set(
    tx - 'authorization',
    '{authorization_list}',
    CASE
        WHEN tx->'authorization' IS NOT NULL AND tx->'authorization' != 'null'::jsonb THEN
            jsonb_build_array(tx->'authorization')
        ELSE
            '[]'::jsonb
    END
)
WHERE tx ? 'quote';