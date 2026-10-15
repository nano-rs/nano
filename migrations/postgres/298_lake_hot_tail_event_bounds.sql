-- Exact per-object event-time bounds let narrow searches prune staged objects
-- within the active hour. The hour partition remains the conservative fallback
-- for objects published before this migration.

ALTER TABLE lake_hot_tail_objects
    ADD COLUMN IF NOT EXISTS min_time_ms bigint,
    ADD COLUMN IF NOT EXISTS max_time_ms bigint;

-- Existing exact objects predate per-file bounds. The hour partition is a
-- conservative, lossless fallback until those objects age out.
UPDATE lake_hot_tail_objects
SET min_time_ms = event_hour::bigint * 3600000,
    max_time_ms = event_hour::bigint * 3600000 + 3599999
WHERE min_time_ms IS NULL OR max_time_ms IS NULL;

ALTER TABLE lake_hot_tail_objects
    ALTER COLUMN min_time_ms SET NOT NULL,
    ALTER COLUMN max_time_ms SET NOT NULL;

ALTER TABLE lake_hot_tail_objects
    DROP CONSTRAINT IF EXISTS lake_hot_tail_objects_event_time_bounds_check,
    ADD CONSTRAINT lake_hot_tail_objects_event_time_bounds_check
        CHECK (min_time_ms > 0 AND max_time_ms >= min_time_ms);

COMMENT ON COLUMN lake_hot_tail_objects.min_time_ms IS
    'Inclusive minimum canonical OCSF event time in this exact Parquet object.';
COMMENT ON COLUMN lake_hot_tail_objects.max_time_ms IS
    'Inclusive maximum canonical OCSF event time in this exact Parquet object.';
