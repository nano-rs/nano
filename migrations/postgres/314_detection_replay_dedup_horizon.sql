-- Late-arrival repair defaults to a seven-day event-time horizon. Keeping its
-- matched-event dedup rows for exactly seven days creates a boundary race: the
-- cleanup can delete a row immediately before the final eligible replay and
-- allow a duplicate alert. These are compact PostgreSQL identity rows, not log
-- payloads, so retain them for 30 days and leave operational headroom around
-- the repair horizon.
CREATE OR REPLACE FUNCTION public.cleanup_old_matched_events() RETURNS void
    LANGUAGE plpgsql
    AS $$
BEGIN
    DELETE FROM detection_matched_events
    WHERE matched_at < NOW() - INTERVAL '30 days';
END;
$$;

COMMENT ON FUNCTION public.cleanup_old_matched_events() IS
    'Removes detection dedup identities after 30 days, safely beyond the default late-replay horizon';
