-- NAN-5839: per-log-source timezone, so every event is stored in true UTC.
--
-- `log_sources.timezone` (migration 087, NOT NULL DEFAULT 'UTC') is the
-- timezone of the source's device clock. The generated Vector config injects
-- it as `.nano.source_timezone`, and the parsers apply it only to a timestamp
-- that carries no offset or zone of its own (parsers#87). 'UTC' is the
-- default: nothing is injected and the parsers read such a clock as UTC.
--
-- The API validates the value (an IANA name known to chrono-tz, or a fixed
-- offset ±HH:MM) and stores it canonical. This constraint is the shape check
-- behind it for every other writer: an IANA-shaped name or a ±HH:MM offset,
-- at most 64 characters. Nothing else can reach the generated config.
--
-- Forward-only and idempotent. A value that does not fit the shape (none
-- should exist: the old validator accepted only 'UTC' and a short list of
-- IANA names) is reset to 'UTC', the behavior it already had, since the
-- renderer never injected an unknown zone. The UPDATE runs only when such a
-- row exists, so the publication trigger (229 / 271, which lists `timezone`)
-- does not republish every source on upgrade.

SET client_min_messages = notice;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM log_sources
        WHERE NOT (
            length(timezone) <= 64
            AND (
                timezone ~ '^[+-][0-9]{2}:[0-9]{2}$'
                OR timezone ~ '^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$'
            )
        )
    ) THEN
        UPDATE log_sources SET timezone = 'UTC'
        WHERE NOT (
            length(timezone) <= 64
            AND (
                timezone ~ '^[+-][0-9]{2}:[0-9]{2}$'
                OR timezone ~ '^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$'
            )
        );
    END IF;
END $$;

DO $$
BEGIN
    ALTER TABLE log_sources
        ADD CONSTRAINT log_sources_timezone_shape CHECK (
            length(timezone) <= 64
            AND (
                timezone ~ '^[+-][0-9]{2}:[0-9]{2}$'
                OR timezone ~ '^[A-Za-z][A-Za-z0-9_+-]*(/[A-Za-z0-9_+-]+){0,2}$'
            )
        );
EXCEPTION WHEN duplicate_object
       OR duplicate_table
       OR duplicate_function
       OR invalid_table_definition
       THEN
    RAISE NOTICE 'idempotent skip (already exists): %', SQLERRM;
END $$;

COMMENT ON COLUMN log_sources.timezone IS
    'NAN-5839: timezone of the source device clock, for timestamps without an offset: an IANA name (America/New_York) or a fixed offset (+05:30). UTC is the default. Injected at ingest as .nano.source_timezone.';
