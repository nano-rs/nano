-- SPDX-License-Identifier: AGPL-3.0-or-later
-- NAN-5079: hash-bound OCSF sample-validation receipt on log sources.
--
-- A parser generation (parser VRL plus its enabled extension) that goes live
-- through publish on an OCSF deployment must have passed VRL execution and
-- OCSF contract validation on at least one representative raw event. The
-- receipt stores only hashes, never sample content. NULL = unattested; sources
-- already live are exempt until their parser changes (no backfill).
ALTER TABLE log_sources
    ADD COLUMN IF NOT EXISTS ocsf_validation_schema_version TEXT,
    ADD COLUMN IF NOT EXISTS ocsf_validation_parser_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS ocsf_validation_sample_sha256 TEXT,
    ADD COLUMN IF NOT EXISTS ocsf_validation_sample_count INTEGER,
    ADD COLUMN IF NOT EXISTS ocsf_validated_at TIMESTAMPTZ;

DO $$
BEGIN
    ALTER TABLE log_sources
        ADD CONSTRAINT log_sources_ocsf_validation_receipt_check CHECK (
            (
                ocsf_validation_schema_version IS NULL
                AND ocsf_validation_parser_sha256 IS NULL
                AND ocsf_validation_sample_sha256 IS NULL
                AND ocsf_validation_sample_count IS NULL
                AND ocsf_validated_at IS NULL
            )
            OR (
                ocsf_validation_schema_version IS NOT NULL
                AND ocsf_validation_parser_sha256 ~ '^[0-9a-f]{64}$'
                AND ocsf_validation_sample_sha256 ~ '^[0-9a-f]{64}$'
                AND ocsf_validation_sample_count > 0
                AND ocsf_validated_at IS NOT NULL
            )
        );
EXCEPTION
    WHEN duplicate_object THEN NULL;
END $$;

COMMENT ON COLUMN log_sources.ocsf_validation_parser_sha256 IS
    'NAN-5079: framed SHA-256 of the OCSF contract version, parser VRL and enabled extension VRL that last passed sample validation';
COMMENT ON COLUMN log_sources.ocsf_validation_sample_sha256 IS
    'NAN-5079: framed SHA-256 of the raw samples that passed; sample content is never stored';
