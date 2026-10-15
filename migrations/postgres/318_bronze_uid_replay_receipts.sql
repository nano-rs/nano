-- NAN-2361: an at-least-once Bronze object may contain only metadata.uid
-- identities already published by earlier exact source batches. It still
-- needs a terminal durable receipt so discovery and physical reclaim can move
-- past the object, but it must not pretend that it created a staged tail or an
-- Iceberg snapshot.

ALTER TABLE lake_bronze_object_publications
    ADD COLUMN IF NOT EXISTS replay_receipt_id text
        CHECK (replay_receipt_id IS NULL OR replay_receipt_id ~ '^[0-9a-f]{64}$');

ALTER TABLE lake_bronze_object_publications
    DROP CONSTRAINT IF EXISTS lake_bronze_publication_state_complete,
    ADD CONSTRAINT lake_bronze_publication_state_complete
        CHECK (
            (
                status = 'pending'
                AND source_rows IS NOT NULL
                AND batch_sha256 IS NOT NULL
                AND event_snapshot_id IS NULL
                AND tail_publication_id IS NULL
                AND replay_receipt_id IS NULL
                AND published_at IS NULL
                AND rejected_at IS NULL
                AND rejection_code IS NULL
            )
            OR
            (
                status = 'published'
                AND source_rows IS NOT NULL
                AND batch_sha256 IS NOT NULL
                AND num_nonnulls(
                    event_snapshot_id,
                    tail_publication_id,
                    replay_receipt_id
                ) = 1
                AND published_at IS NOT NULL
                AND rejected_at IS NULL
                AND rejection_code IS NULL
            )
            OR
            (
                status = 'rejected'
                AND batch_sha256 IS NULL
                AND event_snapshot_id IS NULL
                AND tail_publication_id IS NULL
                AND replay_receipt_id IS NULL
                AND published_at IS NULL
                AND rejected_at IS NOT NULL
                AND rejection_code IS NOT NULL
            )
        );

COMMENT ON COLUMN lake_bronze_object_publications.replay_receipt_id IS
    'Content identity of a source batch whose stable UIDs were all durably published by earlier source batches and which therefore created no canonical rows.';
