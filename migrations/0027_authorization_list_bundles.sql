-- Migrate authorization to authorization_list in bundle_data JSONB columns
-- This completes the migration started in 0025 by handling InteropBundle storage

-- For pending_bundles: migrate authorization to authorization_list in all transactions within bundle_data
-- This updates src_txs, dst_txs, refund_txs, settlement_txs, and execute_receive_txs arrays
UPDATE pending_bundles
SET bundle_data = jsonb_set(
    jsonb_set(
        jsonb_set(
            jsonb_set(
                jsonb_set(
                    bundle_data,
                    '{src_txs}',
                    (
                        SELECT jsonb_agg(
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
                        )
                        FROM jsonb_array_elements(bundle_data->'src_txs') AS tx
                    )
                ),
                '{dst_txs}',
                (
                    SELECT jsonb_agg(
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
                    )
                    FROM jsonb_array_elements(bundle_data->'dst_txs') AS tx
                )
            ),
            '{refund_txs}',
            (
                SELECT jsonb_agg(
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
                )
                FROM jsonb_array_elements(bundle_data->'refund_txs') AS tx
            )
        ),
        '{settlement_txs}',
        (
            SELECT jsonb_agg(
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
            )
            FROM jsonb_array_elements(bundle_data->'settlement_txs') AS tx
        )
    ),
    '{execute_receive_txs}',
    (
        SELECT jsonb_agg(
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
        )
        FROM jsonb_array_elements(bundle_data->'execute_receive_txs') AS tx
    )
)
WHERE
    bundle_data::text LIKE '%"authorization":%';

-- For finished_bundles: migrate authorization to authorization_list in all transactions within bundle_data
UPDATE finished_bundles
SET bundle_data = jsonb_set(
    jsonb_set(
        jsonb_set(
            jsonb_set(
                jsonb_set(
                    bundle_data,
                    '{src_txs}',
                    (
                        SELECT jsonb_agg(
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
                        )
                        FROM jsonb_array_elements(bundle_data->'src_txs') AS tx
                    )
                ),
                '{dst_txs}',
                (
                    SELECT jsonb_agg(
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
                    )
                    FROM jsonb_array_elements(bundle_data->'dst_txs') AS tx
                )
            ),
            '{refund_txs}',
            (
                SELECT jsonb_agg(
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
                )
                FROM jsonb_array_elements(bundle_data->'refund_txs') AS tx
            )
        ),
        '{settlement_txs}',
        (
            SELECT jsonb_agg(
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
            )
            FROM jsonb_array_elements(bundle_data->'settlement_txs') AS tx
        )
    ),
    '{execute_receive_txs}',
    (
        SELECT jsonb_agg(
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
        )
        FROM jsonb_array_elements(bundle_data->'execute_receive_txs') AS tx
    )
)
WHERE
    bundle_data::text LIKE '%"authorization":%';
