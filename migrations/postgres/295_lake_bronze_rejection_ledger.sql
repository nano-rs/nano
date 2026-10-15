-- NAN-2361: permanently isolate exact Vector bronze objects whose immutable
-- bytes fail strict OCSF admission. Transient object-store/catalog failures
-- never enter this state; the Rust coordinator records it only after an exact
-- version was downloaded and deterministically rejected by the local parser.

ALTER TABLE lake_bronze_object_publications
    ALTER COLUMN source_rows DROP NOT NULL,
    ALTER COLUMN batch_sha256 DROP NOT NULL,
    ADD COLUMN rejected_at timestamptz,
    ADD COLUMN rejection_code text;

ALTER TABLE lake_bronze_object_publications
    DROP CONSTRAINT lake_bronze_object_publications_status_check,
    DROP CONSTRAINT lake_bronze_object_publications_check,
    ADD CONSTRAINT lake_bronze_object_publications_status_check
        CHECK (status IN ('pending', 'published', 'rejected')),
    ADD CONSTRAINT lake_bronze_rejection_code_canonical
        CHECK (
            rejection_code IS NULL
            OR rejection_code ~ '^[a-z][a-z0-9_]{0,63}$'
        ),
    ADD CONSTRAINT lake_bronze_publication_state_complete
        CHECK (
            (
                status = 'pending'
                AND source_rows IS NOT NULL
                AND batch_sha256 IS NOT NULL
                AND event_snapshot_id IS NULL
                AND published_at IS NULL
                AND rejected_at IS NULL
                AND rejection_code IS NULL
            )
            OR
            (
                status = 'published'
                AND source_rows IS NOT NULL
                AND batch_sha256 IS NOT NULL
                AND event_snapshot_id IS NOT NULL
                AND published_at IS NOT NULL
                AND rejected_at IS NULL
                AND rejection_code IS NULL
            )
            OR
            (
                status = 'rejected'
                AND batch_sha256 IS NULL
                AND event_snapshot_id IS NULL
                AND published_at IS NULL
                AND rejected_at IS NOT NULL
                AND rejection_code IS NOT NULL
            )
        );

COMMENT ON COLUMN lake_bronze_object_publications.rejected_at IS
    'Time an exact immutable object version deterministically failed strict local admission; NULL for retryable infrastructure failures.';
COMMENT ON COLUMN lake_bronze_object_publications.rejection_code IS
    'Bounded machine-readable reason for an exact object quarantine; details are retained in last_error.';
