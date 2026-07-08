-- Audit D18 (NAN-1712): bound detection_matches growth.
--
-- detection_matches stores the full matched-events JSONB per firing for the
-- rule-detail "matches" view. Nothing ever deleted from it and it has no TTL,
-- and drifting-count hashes defeat the unique constraint's bounding, so it grows
-- unbounded on the hot metadata PG. This adds a 30-day retention (generous
-- enough for the rule sparkline / match history, but finite) swept by the hourly
-- detection-dedup cleanup task. Returns the number of rows removed for logging.

CREATE OR REPLACE FUNCTION public.cleanup_old_detection_matches() RETURNS bigint
    LANGUAGE plpgsql
    AS $$
DECLARE
    deleted bigint;
BEGIN
    WITH d AS (
        DELETE FROM public.detection_matches
        WHERE detected_at < NOW() - INTERVAL '30 days'
        RETURNING 1
    )
    SELECT COUNT(*) INTO deleted FROM d;
    RETURN deleted;
END;
$$;
