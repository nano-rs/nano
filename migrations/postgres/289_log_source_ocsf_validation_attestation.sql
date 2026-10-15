-- Persist only a hash-bound validation receipt, never customer sample content.
-- The parser fingerprint includes the enabled extension VRL, so editing either
-- stage invalidates the receipt without relying on application-side cleanup.
ALTER TABLE log_sources
    ADD COLUMN IF NOT EXISTS ocsf_validation_schema_version TEXT,
    ADD COLUMN IF NOT EXISTS ocsf_validation_parser_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS ocsf_validation_sample_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS ocsf_validation_sample_count INTEGER,
    ADD COLUMN IF NOT EXISTS ocsf_validated_at TIMESTAMPTZ;

ALTER TABLE log_sources
    DROP CONSTRAINT IF EXISTS log_sources_ocsf_validation_hashes_check;

ALTER TABLE log_sources
    ADD CONSTRAINT log_sources_ocsf_validation_hashes_check CHECK (
        (ocsf_validation_parser_sha256 IS NULL AND ocsf_validation_sample_sha256 IS NULL)
        OR (
            ocsf_validation_parser_sha256 ~ '^[0-9a-f]{64}$'
            AND ocsf_validation_sample_sha256 ~ '^[0-9a-f]{64}$'
            AND ocsf_validation_sample_count > 0
            AND ocsf_validated_at IS NOT NULL
        )
    );

COMMENT ON COLUMN log_sources.ocsf_validation_parser_sha256 IS
    'SHA-256 of parser VRL plus enabled extension VRL at the successful OCSF sample gate';
COMMENT ON COLUMN log_sources.ocsf_validation_sample_sha256 IS
    'SHA-256 receipt for the validated raw samples; sample content is intentionally not retained';
