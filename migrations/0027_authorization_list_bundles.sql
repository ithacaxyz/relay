-- Migrate authorization to authorization_list in bundle_data JSONB columns
-- This completes the migration started in 0025 by handling InteropBundle storage

-- For pending_bundles: migrate authorization to authorization_list in all transactions within bundle_data
-- This updates src_txs, dst_txs, refund_txs, settlement_txs, and execute_receive_txs arrays
UPDATE pending_bundles
SET bundle_data = bundle_data || jsonb_build_object(
    'src_txs', (
        SELECT COALESCE(jsonb_agg(
            CASE
                WHEN tx ? 'quote' AND tx ? 'authorization' THEN
                    jsonb_set(
                        tx - 'authorization',
                        '{authorization_list}',
                        CASE
                            WHEN tx->'authorization' IS NOT NULL AND tx->'authorization' != 'null'::jsonb THEN
                                jsonb_build_array(tx->'authorization')
                            ELSE
                                '[]'::jsonb
                        END
                    )
                ELSE tx
            END
        ), '[]'::jsonb)
        FROM jsonb_array_elements(COALESCE(bundle_data->'src_txs', '[]'::jsonb)) AS tx
    ),
    'dst_txs', (
        SELECT COALESCE(jsonb_agg(
            CASE
                WHEN tx ? 'quote' AND tx ? 'authorization' THEN
                    jsonb_set(
                        tx - 'authorization',
                        '{authorization_list}',
                        CASE
                            WHEN tx->'authorization' IS NOT NULL AND tx->'authorization' != 'null'::jsonb THEN
                                jsonb_build_array(tx->'authorization')
                            ELSE
                                '[]'::jsonb
                        END
                    )
                ELSE tx
            END
        ), '[]'::jsonb)
        FROM jsonb_array_elements(COALESCE(bundle_data->'dst_txs', '[]'::jsonb)) AS tx
    ),
    'refund_txs', (
        SELECT COALESCE(jsonb_agg(
            CASE
                WHEN tx ? 'quote' AND tx ? 'authorization' THEN
                    jsonb_set(
                        tx - 'authorization',
                        '{authorization_list}',
                        CASE
                            WHEN tx->'authorization' IS NOT NULL AND tx->'authorization' != 'null'::jsonb THEN
                                jsonb_build_array(tx->'authorization')
                            ELSE
                                '[]'::jsonb
                        END
                    )
                ELSE tx
            END
        ), '[]'::jsonb)
        FROM jsonb_array_elements(COALESCE(bundle_data->'refund_txs', '[]'::jsonb)) AS tx
    ),
    'settlement_txs', (
        SELECT COALESCE(jsonb_agg(
            CASE
                WHEN tx ? 'quote' AND tx ? 'authorization' THEN
                    jsonb_set(
                        tx - 'authorization',
                        '{authorization_list}',
                        CASE
                            WHEN tx->'authorization' IS NOT NULL AND tx->'authorization' != 'null'::jsonb THEN
                                jsonb_build_array(tx->'authorization')
                            ELSE
                                '[]'::jsonb
                        END
                    )
                ELSE tx
            END
        ), '[]'::jsonb)
        FROM jsonb_array_elements(COALESCE(bundle_data->'settlement_txs', '[]'::jsonb)) AS tx
    ),
    'execute_receive_txs', (
        SELECT COALESCE(jsonb_agg(
            CASE
                WHEN tx ? 'quote' AND tx ? 'authorization' THEN
                    jsonb_set(
                        tx - 'authorization',
                        '{authorization_list}',
                        CASE
                            WHEN tx->'authorization' IS NOT NULL AND tx->'authorization' != 'null'::jsonb THEN
                                jsonb_build_array(tx->'authorization')
                            ELSE
                                '[]'::jsonb
                        END
                    )
                ELSE tx
            END
        ), '[]'::jsonb)
        FROM jsonb_array_elements(COALESCE(bundle_data->'execute_receive_txs', '[]'::jsonb)) AS tx
    )
)
WHERE
    jsonb_path_exists(bundle_data, '$.** ? (exists(@.authorization))');

-- For finished_bundles: migrate authorization to authorization_list in all transactions within bundle_data
UPDATE finished_bundles
SET bundle_data = bundle_data || jsonb_build_object(
    'src_txs', (
        SELECT COALESCE(jsonb_agg(
            CASE
                WHEN tx ? 'quote' AND tx ? 'authorization' THEN
                    jsonb_set(
                        tx - 'authorization',
                        '{authorization_list}',
                        CASE
                            WHEN tx->'authorization' IS NOT NULL AND tx->'authorization' != 'null'::jsonb THEN
                                jsonb_build_array(tx->'authorization')
                            ELSE
                                '[]'::jsonb
                        END
                    )
                ELSE tx
            END
        ), '[]'::jsonb)
        FROM jsonb_array_elements(COALESCE(bundle_data->'src_txs', '[]'::jsonb)) AS tx
    ),
    'dst_txs', (
        SELECT COALESCE(jsonb_agg(
            CASE
                WHEN tx ? 'quote' AND tx ? 'authorization' THEN
                    jsonb_set(
                        tx - 'authorization',
                        '{authorization_list}',
                        CASE
                            WHEN tx->'authorization' IS NOT NULL AND tx->'authorization' != 'null'::jsonb THEN
                                jsonb_build_array(tx->'authorization')
                            ELSE
                                '[]'::jsonb
                        END
                    )
                ELSE tx
            END
        ), '[]'::jsonb)
        FROM jsonb_array_elements(COALESCE(bundle_data->'dst_txs', '[]'::jsonb)) AS tx
    ),
    'refund_txs', (
        SELECT COALESCE(jsonb_agg(
            CASE
                WHEN tx ? 'quote' AND tx ? 'authorization' THEN
                    jsonb_set(
                        tx - 'authorization',
                        '{authorization_list}',
                        CASE
                            WHEN tx->'authorization' IS NOT NULL AND tx->'authorization' != 'null'::jsonb THEN
                                jsonb_build_array(tx->'authorization')
                            ELSE
                                '[]'::jsonb
                        END
                    )
                ELSE tx
            END
        ), '[]'::jsonb)
        FROM jsonb_array_elements(COALESCE(bundle_data->'refund_txs', '[]'::jsonb)) AS tx
    ),
    'settlement_txs', (
        SELECT COALESCE(jsonb_agg(
            CASE
                WHEN tx ? 'quote' AND tx ? 'authorization' THEN
                    jsonb_set(
                        tx - 'authorization',
                        '{authorization_list}',
                        CASE
                            WHEN tx->'authorization' IS NOT NULL AND tx->'authorization' != 'null'::jsonb THEN
                                jsonb_build_array(tx->'authorization')
                            ELSE
                                '[]'::jsonb
                        END
                    )
                ELSE tx
            END
        ), '[]'::jsonb)
        FROM jsonb_array_elements(COALESCE(bundle_data->'settlement_txs', '[]'::jsonb)) AS tx
    ),
    'execute_receive_txs', (
        SELECT COALESCE(jsonb_agg(
            CASE
                WHEN tx ? 'quote' AND tx ? 'authorization' THEN
                    jsonb_set(
                        tx - 'authorization',
                        '{authorization_list}',
                        CASE
                            WHEN tx->'authorization' IS NOT NULL AND tx->'authorization' != 'null'::jsonb THEN
                                jsonb_build_array(tx->'authorization')
                            ELSE
                                '[]'::jsonb
                        END
                    )
                ELSE tx
            END
        ), '[]'::jsonb)
        FROM jsonb_array_elements(COALESCE(bundle_data->'execute_receive_txs', '[]'::jsonb)) AS tx
    )
)
WHERE
    jsonb_path_exists(bundle_data, '$.** ? (exists(@.authorization))');
